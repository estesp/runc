// +build linux

package libcontainer

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/golang/protobuf/proto"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/criurpc"
)

const stdioFdCount = 3

type linuxContainer struct {
	id            string
	root          string
	config        *configs.Config
	cgroupManager cgroups.Manager
	initPath      string
	initArgs      []string
	initProcess   parentProcess
	criuPath      string
	m             sync.Mutex
}

// ID returns the container's unique ID
func (c *linuxContainer) ID() string {
	return c.id
}

// Config returns the container's configuration
func (c *linuxContainer) Config() configs.Config {
	return *c.config
}

func (c *linuxContainer) Status() (Status, error) {
	c.m.Lock()
	defer c.m.Unlock()
	return c.currentStatus()
}

func (c *linuxContainer) State() (*State, error) {
	c.m.Lock()
	defer c.m.Unlock()
	return c.currentState()
}

func (c *linuxContainer) Processes() ([]int, error) {
	pids, err := c.cgroupManager.GetPids()
	if err != nil {
		return nil, newSystemError(err)
	}
	return pids, nil
}

func (c *linuxContainer) Stats() (*Stats, error) {
	var (
		err   error
		stats = &Stats{}
	)
	if stats.CgroupStats, err = c.cgroupManager.GetStats(); err != nil {
		return stats, newSystemError(err)
	}
	for _, iface := range c.config.Networks {
		switch iface.Type {
		case "veth":
			istats, err := getNetworkInterfaceStats(iface.HostInterfaceName)
			if err != nil {
				return stats, newSystemError(err)
			}
			stats.Interfaces = append(stats.Interfaces, istats)
		}
	}
	return stats, nil
}

func (c *linuxContainer) Set(config configs.Config) error {
	c.m.Lock()
	defer c.m.Unlock()
	c.config = &config
	return c.cgroupManager.Set(c.config)
}

func (c *linuxContainer) Start(process *Process) error {
	c.m.Lock()
	defer c.m.Unlock()
	status, err := c.currentStatus()
	if err != nil {
		return err
	}
	doInit := status == Destroyed
	parent, err := c.newParentProcess(process, doInit)
	if err != nil {
		return newSystemError(err)
	}
	if err := parent.start(); err != nil {
		// terminate the process to ensure that it properly is reaped.
		if err := parent.terminate(); err != nil {
			logrus.Warn(err)
		}
		return newSystemError(err)
	}
	process.ops = parent
	if doInit {
		c.updateState(parent)
	}
	return nil
}

func (c *linuxContainer) Signal(s os.Signal) error {
	if err := c.initProcess.signal(s); err != nil {
		return newSystemError(err)
	}
	return nil
}

func (c *linuxContainer) newParentProcess(p *Process, doInit bool) (parentProcess, error) {
	parentPipe, childPipe, err := newPipe()
	if err != nil {
		return nil, newSystemError(err)
	}
	cmd, err := c.commandTemplate(p, childPipe)
	if err != nil {
		return nil, newSystemError(err)
	}
	if !doInit {
		return c.newSetnsProcess(p, cmd, parentPipe, childPipe)
	}
	return c.newInitProcess(p, cmd, parentPipe, childPipe)
}

func (c *linuxContainer) commandTemplate(p *Process, childPipe *os.File) (*exec.Cmd, error) {
	cmd := &exec.Cmd{
		Path: c.initPath,
		Args: c.initArgs,
	}
	cmd.Stdin = p.Stdin
	cmd.Stdout = p.Stdout
	cmd.Stderr = p.Stderr
	cmd.Dir = c.config.Rootfs
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.ExtraFiles = append(p.ExtraFiles, childPipe)
	cmd.Env = append(cmd.Env, fmt.Sprintf("_LIBCONTAINER_INITPIPE=%d", stdioFdCount+len(cmd.ExtraFiles)-1))
	// NOTE: when running a container with no PID namespace and the parent process spawning the container is
	// PID1 the pdeathsig is being delivered to the container's init process by the kernel for some reason
	// even with the parent still running.
	if c.config.ParentDeathSignal > 0 {
		cmd.SysProcAttr.Pdeathsig = syscall.Signal(c.config.ParentDeathSignal)
	}
	return cmd, nil
}

func (c *linuxContainer) newInitProcess(p *Process, cmd *exec.Cmd, parentPipe, childPipe *os.File) (*initProcess, error) {
	cmd.Env = append(cmd.Env, "_LIBCONTAINER_INITTYPE=standard")
	nsMaps := make(map[configs.NamespaceType]string)
	for _, ns := range c.config.Namespaces {
		if ns.Path != "" {
			nsMaps[ns.Type] = ns.Path
		}
	}
	_, sharePidns := nsMaps[configs.NEWPID]
	data, err := c.bootstrapData(cmd, c.config.Namespaces.CloneFlags(), nsMaps, "")
	if err != nil {
		return nil, err
	}
	return &initProcess{
		cmd:           cmd,
		childPipe:     childPipe,
		parentPipe:    parentPipe,
		manager:       c.cgroupManager,
		config:        c.newInitConfig(p),
		bootstrapData: data,
		sharePidns:    sharePidns,
	}, nil
}

func (c *linuxContainer) newSetnsProcess(p *Process, cmd *exec.Cmd, parentPipe, childPipe *os.File) (*setnsProcess, error) {
	cmd.Env = append(cmd.Env, "_LIBCONTAINER_INITTYPE=setns")
	state, err := c.currentState()
	if err != nil {
		return nil, newSystemError(err)
	}
	// for setns process, we dont have to set cloneflags as the process namespaces
	// will only be set via setns syscall
	data, err := c.bootstrapData(cmd, 0, state.NamespacePaths, p.consolePath)
	if err != nil {
		return nil, err
	}
	// TODO: set on container for process management
	return &setnsProcess{
		cmd:           cmd,
		cgroupPaths:   c.cgroupManager.GetPaths(),
		childPipe:     childPipe,
		parentPipe:    parentPipe,
		config:        c.newInitConfig(p),
		bootstrapData: data,
	}, nil
}

func (c *linuxContainer) newInitConfig(process *Process) *initConfig {
	return &initConfig{
		Config:           c.config,
		Args:             process.Args,
		Env:              process.Env,
		User:             process.User,
		Cwd:              process.Cwd,
		Console:          process.consolePath,
		Capabilities:     process.Capabilities,
		PassedFilesCount: len(process.ExtraFiles),
	}
}

func newPipe() (parent *os.File, child *os.File, err error) {
	fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(fds[1]), "parent"), os.NewFile(uintptr(fds[0]), "child"), nil
}

func (c *linuxContainer) Destroy() error {
	c.m.Lock()
	defer c.m.Unlock()
	status, err := c.currentStatus()
	if err != nil {
		return err
	}
	if status != Destroyed {
		return newGenericError(fmt.Errorf("container is not destroyed"), ContainerNotStopped)
	}
	if !c.config.Namespaces.Contains(configs.NEWPID) {
		if err := killCgroupProcesses(c.cgroupManager); err != nil {
			logrus.Warn(err)
		}
	}
	err = c.cgroupManager.Destroy()
	if rerr := os.RemoveAll(c.root); err == nil {
		err = rerr
	}
	c.initProcess = nil
	return err
}

func (c *linuxContainer) Pause() error {
	c.m.Lock()
	defer c.m.Unlock()
	return c.cgroupManager.Freeze(configs.Frozen)
}

func (c *linuxContainer) Resume() error {
	c.m.Lock()
	defer c.m.Unlock()
	return c.cgroupManager.Freeze(configs.Thawed)
}

func (c *linuxContainer) NotifyOOM() (<-chan struct{}, error) {
	return notifyOnOOM(c.cgroupManager.GetPaths())
}

// XXX debug support, remove when debugging done.
func addArgsFromEnv(evar string, args *[]string) {
	if e := os.Getenv(evar); e != "" {
		for _, f := range strings.Fields(e) {
			*args = append(*args, f)
		}
	}
	fmt.Printf(">>> criu %v\n", *args)
}

func (c *linuxContainer) checkCriuVersion() error {
	var x, y, z int

	out, err := exec.Command(c.criuPath, "-V").Output()
	if err != nil {
		return fmt.Errorf("Unable to execute CRIU command: %s", c.criuPath)
	}

	n, err := fmt.Sscanf(string(out), "Version: %d.%d.%d\n", &x, &y, &z) // 1.5.2
	if err != nil {
		n, err = fmt.Sscanf(string(out), "Version: %d.%d\n", &x, &y) // 1.6
	}
	if n < 2 || err != nil {
		return fmt.Errorf("Unable to parse the CRIU version: %s %d %s", out, n, err)
	}

	if x*10000+y*100+z < 10502 {
		return fmt.Errorf("CRIU version must be 1.5.2 or higher")
	}

	return nil
}

const descriptorsFilename = "descriptors.json"

func (c *linuxContainer) addCriuDumpMount(req *criurpc.CriuReq, m *configs.Mount) {
	mountDest := m.Destination
	if strings.HasPrefix(mountDest, c.config.Rootfs) {
		mountDest = mountDest[len(c.config.Rootfs):]
	}

	extMnt := &criurpc.ExtMountMap{
		Key: proto.String(mountDest),
		Val: proto.String(mountDest),
	}
	req.Opts.ExtMnt = append(req.Opts.ExtMnt, extMnt)
}

func (c *linuxContainer) Checkpoint(criuOpts *CriuOpts) error {
	c.m.Lock()
	defer c.m.Unlock()

	if err := c.checkCriuVersion(); err != nil {
		return err
	}

	if criuOpts.ImagesDirectory == "" {
		criuOpts.ImagesDirectory = filepath.Join(c.root, "criu.image")
	}

	// Since a container can be C/R'ed multiple times,
	// the checkpoint directory may already exist.
	if err := os.Mkdir(criuOpts.ImagesDirectory, 0755); err != nil && !os.IsExist(err) {
		return err
	}

	if criuOpts.WorkDirectory == "" {
		criuOpts.WorkDirectory = filepath.Join(c.root, "criu.work")
	}

	if err := os.Mkdir(criuOpts.WorkDirectory, 0755); err != nil && !os.IsExist(err) {
		return err
	}

	workDir, err := os.Open(criuOpts.WorkDirectory)
	if err != nil {
		return err
	}
	defer workDir.Close()

	imageDir, err := os.Open(criuOpts.ImagesDirectory)
	if err != nil {
		return err
	}
	defer imageDir.Close()

	rpcOpts := criurpc.CriuOpts{
		ImagesDirFd:    proto.Int32(int32(imageDir.Fd())),
		WorkDirFd:      proto.Int32(int32(workDir.Fd())),
		LogLevel:       proto.Int32(4),
		LogFile:        proto.String("dump.log"),
		Root:           proto.String(c.config.Rootfs),
		ManageCgroups:  proto.Bool(true),
		NotifyScripts:  proto.Bool(true),
		Pid:            proto.Int32(int32(c.initProcess.pid())),
		ShellJob:       proto.Bool(criuOpts.ShellJob),
		LeaveRunning:   proto.Bool(criuOpts.LeaveRunning),
		TcpEstablished: proto.Bool(criuOpts.TcpEstablished),
		ExtUnixSk:      proto.Bool(criuOpts.ExternalUnixConnections),
		FileLocks:      proto.Bool(criuOpts.FileLocks),
	}

	// append optional criu opts, e.g., page-server and port
	if criuOpts.PageServer.Address != "" && criuOpts.PageServer.Port != 0 {
		rpcOpts.Ps = &criurpc.CriuPageServerInfo{
			Address: proto.String(criuOpts.PageServer.Address),
			Port:    proto.Int32(criuOpts.PageServer.Port),
		}
	}

	t := criurpc.CriuReqType_DUMP
	req := &criurpc.CriuReq{
		Type: &t,
		Opts: &rpcOpts,
	}

	for _, m := range c.config.Mounts {
		switch m.Device {
		case "bind":
			c.addCriuDumpMount(req, m)
			break
		case "cgroup":
			binds, err := getCgroupMounts(m)
			if err != nil {
				return err
			}
			for _, b := range binds {
				c.addCriuDumpMount(req, b)
			}
			break
		}
	}

	// Write the FD info to a file in the image directory

	fdsJSON, err := json.Marshal(c.initProcess.externalDescriptors())
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filepath.Join(criuOpts.ImagesDirectory, descriptorsFilename), fdsJSON, 0655)
	if err != nil {
		return err
	}

	err = c.criuSwrk(nil, req, criuOpts)
	if err != nil {
		return err
	}
	return nil
}

func (c *linuxContainer) addCriuRestoreMount(req *criurpc.CriuReq, m *configs.Mount) {
	mountDest := m.Destination
	if strings.HasPrefix(mountDest, c.config.Rootfs) {
		mountDest = mountDest[len(c.config.Rootfs):]
	}

	extMnt := &criurpc.ExtMountMap{
		Key: proto.String(mountDest),
		Val: proto.String(m.Source),
	}
	req.Opts.ExtMnt = append(req.Opts.ExtMnt, extMnt)
}

func (c *linuxContainer) Restore(process *Process, criuOpts *CriuOpts) error {
	c.m.Lock()
	defer c.m.Unlock()

	if err := c.checkCriuVersion(); err != nil {
		return err
	}

	if criuOpts.WorkDirectory == "" {
		criuOpts.WorkDirectory = filepath.Join(c.root, "criu.work")
	}
	// Since a container can be C/R'ed multiple times,
	// the work directory may already exist.
	if err := os.Mkdir(criuOpts.WorkDirectory, 0655); err != nil && !os.IsExist(err) {
		return err
	}

	workDir, err := os.Open(criuOpts.WorkDirectory)
	if err != nil {
		return err
	}
	defer workDir.Close()

	if criuOpts.ImagesDirectory == "" {
		criuOpts.ImagesDirectory = filepath.Join(c.root, "criu.image")
	}
	imageDir, err := os.Open(criuOpts.ImagesDirectory)
	if err != nil {
		return err
	}
	defer imageDir.Close()

	// CRIU has a few requirements for a root directory:
	// * it must be a mount point
	// * its parent must not be overmounted
	// c.config.Rootfs is bind-mounted to a temporary directory
	// to satisfy these requirements.
	root := filepath.Join(c.root, "criu-root")
	if err := os.Mkdir(root, 0755); err != nil {
		return err
	}
	defer os.Remove(root)

	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}

	err = syscall.Mount(c.config.Rootfs, root, "", syscall.MS_BIND|syscall.MS_REC, "")
	if err != nil {
		return err
	}
	defer syscall.Unmount(root, syscall.MNT_DETACH)

	t := criurpc.CriuReqType_RESTORE
	req := &criurpc.CriuReq{
		Type: &t,
		Opts: &criurpc.CriuOpts{
			ImagesDirFd:    proto.Int32(int32(imageDir.Fd())),
			WorkDirFd:      proto.Int32(int32(workDir.Fd())),
			EvasiveDevices: proto.Bool(true),
			LogLevel:       proto.Int32(4),
			LogFile:        proto.String("restore.log"),
			RstSibling:     proto.Bool(true),
			Root:           proto.String(root),
			ManageCgroups:  proto.Bool(true),
			NotifyScripts:  proto.Bool(true),
			ShellJob:       proto.Bool(criuOpts.ShellJob),
			ExtUnixSk:      proto.Bool(criuOpts.ExternalUnixConnections),
			TcpEstablished: proto.Bool(criuOpts.TcpEstablished),
			FileLocks:      proto.Bool(criuOpts.FileLocks),
		},
	}
	for _, m := range c.config.Mounts {
		switch m.Device {
		case "bind":
			c.addCriuRestoreMount(req, m)
			break
		case "cgroup":
			binds, err := getCgroupMounts(m)
			if err != nil {
				return err
			}
			for _, b := range binds {
				c.addCriuRestoreMount(req, b)
			}
			break
		}
	}
	for _, iface := range c.config.Networks {
		switch iface.Type {
		case "veth":
			veth := new(criurpc.CriuVethPair)
			veth.IfOut = proto.String(iface.HostInterfaceName)
			veth.IfIn = proto.String(iface.Name)
			req.Opts.Veths = append(req.Opts.Veths, veth)
			break
		case "loopback":
			break
		}
	}
	for _, i := range criuOpts.VethPairs {
		veth := new(criurpc.CriuVethPair)
		veth.IfOut = proto.String(i.HostInterfaceName)
		veth.IfIn = proto.String(i.ContainerInterfaceName)
		req.Opts.Veths = append(req.Opts.Veths, veth)
	}

	var (
		fds    []string
		fdJSON []byte
	)

	if fdJSON, err = ioutil.ReadFile(filepath.Join(criuOpts.ImagesDirectory, descriptorsFilename)); err != nil {
		return err
	}

	if err = json.Unmarshal(fdJSON, &fds); err != nil {
		return err
	}

	for i := range fds {
		if s := fds[i]; strings.Contains(s, "pipe:") {
			inheritFd := new(criurpc.InheritFd)
			inheritFd.Key = proto.String(s)
			inheritFd.Fd = proto.Int32(int32(i))
			req.Opts.InheritFd = append(req.Opts.InheritFd, inheritFd)
		}
	}

	err = c.criuSwrk(process, req, criuOpts)
	if err != nil {
		return err
	}
	return nil
}

func (c *linuxContainer) criuSwrk(process *Process, req *criurpc.CriuReq, opts *CriuOpts) error {
	fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}

	logPath := filepath.Join(opts.WorkDirectory, req.GetOpts().GetLogFile())
	criuClient := os.NewFile(uintptr(fds[0]), "criu-transport-client")
	criuServer := os.NewFile(uintptr(fds[1]), "criu-transport-server")
	defer criuClient.Close()
	defer criuServer.Close()

	args := []string{"swrk", "3"}
	cmd := exec.Command(c.criuPath, args...)
	if process != nil {
		cmd.Stdin = process.Stdin
		cmd.Stdout = process.Stdout
		cmd.Stderr = process.Stderr
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, criuServer)

	if err := cmd.Start(); err != nil {
		return err
	}
	criuServer.Close()

	defer func() {
		criuClient.Close()
		_, err := cmd.Process.Wait()
		if err != nil {
			return
		}
	}()

	var extFds []string
	if process != nil {
		extFds, err = getPipeFds(cmd.Process.Pid)
		if err != nil {
			return err
		}
	}

	data, err := proto.Marshal(req)
	if err != nil {
		return err
	}
	_, err = criuClient.Write(data)
	if err != nil {
		return err
	}

	buf := make([]byte, 10*4096)
	for true {
		n, err := criuClient.Read(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("unexpected EOF")
		}
		if n == len(buf) {
			return fmt.Errorf("buffer is too small")
		}

		resp := new(criurpc.CriuResp)
		err = proto.Unmarshal(buf[:n], resp)
		if err != nil {
			return err
		}
		if !resp.GetSuccess() {
			typeString := req.GetType().String()
			return fmt.Errorf("criu failed: type %s errno %d\nlog file: %s", typeString, resp.GetCrErrno(), logPath)
		}

		t := resp.GetType()
		switch {
		case t == criurpc.CriuReqType_NOTIFY:
			if err := c.criuNotifications(resp, process, opts, extFds); err != nil {
				return err
			}
			t = criurpc.CriuReqType_NOTIFY
			req = &criurpc.CriuReq{
				Type:          &t,
				NotifySuccess: proto.Bool(true),
			}
			data, err = proto.Marshal(req)
			if err != nil {
				return err
			}
			n, err = criuClient.Write(data)
			if err != nil {
				return err
			}
			continue
		case t == criurpc.CriuReqType_RESTORE:
		case t == criurpc.CriuReqType_DUMP:
			break
		default:
			return fmt.Errorf("unable to parse the response %s", resp.String())
		}

		break
	}

	// cmd.Wait() waits cmd.goroutines which are used for proxying file descriptors.
	// Here we want to wait only the CRIU process.
	st, err := cmd.Process.Wait()
	if err != nil {
		return err
	}
	if !st.Success() {
		return fmt.Errorf("criu failed: %s\nlog file: %s", st.String(), logPath)
	}
	return nil
}

// block any external network activity
func lockNetwork(config *configs.Config) error {
	for _, config := range config.Networks {
		strategy, err := getStrategy(config.Type)
		if err != nil {
			return err
		}

		if err := strategy.detach(config); err != nil {
			return err
		}
	}
	return nil
}

func unlockNetwork(config *configs.Config) error {
	for _, config := range config.Networks {
		strategy, err := getStrategy(config.Type)
		if err != nil {
			return err
		}
		if err = strategy.attach(config); err != nil {
			return err
		}
	}
	return nil
}

func (c *linuxContainer) criuNotifications(resp *criurpc.CriuResp, process *Process, opts *CriuOpts, fds []string) error {
	notify := resp.GetNotify()
	if notify == nil {
		return fmt.Errorf("invalid response: %s", resp.String())
	}

	switch {
	case notify.GetScript() == "post-dump":
		if !opts.LeaveRunning {
			f, err := os.Create(filepath.Join(c.root, "checkpoint"))
			if err != nil {
				return err
			}
			f.Close()
		}
		break

	case notify.GetScript() == "network-unlock":
		if err := unlockNetwork(c.config); err != nil {
			return err
		}
		break

	case notify.GetScript() == "network-lock":
		if err := lockNetwork(c.config); err != nil {
			return err
		}
		break

	case notify.GetScript() == "post-restore":
		pid := notify.GetPid()
		r, err := newRestoredProcess(int(pid), fds)
		if err != nil {
			return err
		}

		// TODO: crosbymichael restore previous process information by saving the init process information in
		// the container's state file or separate process state files.
		if err := c.updateState(r); err != nil {
			return err
		}
		process.ops = r
		break
	}

	return nil
}

func (c *linuxContainer) updateState(process parentProcess) error {
	c.initProcess = process
	state, err := c.currentState()
	if err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(c.root, stateFilename))
	if err != nil {
		return err
	}
	defer f.Close()
	os.Remove(filepath.Join(c.root, "checkpoint"))
	return json.NewEncoder(f).Encode(state)
}

func (c *linuxContainer) currentStatus() (Status, error) {
	if _, err := os.Stat(filepath.Join(c.root, "checkpoint")); err == nil {
		return Checkpointed, nil
	}
	if c.initProcess == nil {
		return Destroyed, nil
	}
	// return Running if the init process is alive
	if err := syscall.Kill(c.initProcess.pid(), 0); err != nil {
		if err == syscall.ESRCH {
			return Destroyed, nil
		}
		return 0, newSystemError(err)
	}
	if c.config.Cgroups != nil && c.config.Cgroups.Freezer == configs.Frozen {
		return Paused, nil
	}
	return Running, nil
}

func (c *linuxContainer) currentState() (*State, error) {
	status, err := c.currentStatus()
	if err != nil {
		return nil, err
	}
	if status == Destroyed {
		return nil, newGenericError(fmt.Errorf("container destroyed"), ContainerNotExists)
	}
	startTime, err := c.initProcess.startTime()
	if err != nil {
		return nil, newSystemError(err)
	}
	state := &State{
		ID:                   c.ID(),
		Config:               *c.config,
		InitProcessPid:       c.initProcess.pid(),
		InitProcessStartTime: startTime,
		CgroupPaths:          c.cgroupManager.GetPaths(),
		NamespacePaths:       make(map[configs.NamespaceType]string),
		ExternalDescriptors:  c.initProcess.externalDescriptors(),
	}
	for _, ns := range c.config.Namespaces {
		state.NamespacePaths[ns.Type] = ns.GetPath(c.initProcess.pid())
	}
	for _, nsType := range configs.NamespaceTypes() {
		if _, ok := state.NamespacePaths[nsType]; !ok {
			ns := configs.Namespace{Type: nsType}
			state.NamespacePaths[ns.Type] = ns.GetPath(c.initProcess.pid())
		}
	}
	return state, nil
}

// orderNamespacePaths sorts that namespace paths into a list of paths that we
// can safely setns to.
func (c *linuxContainer) orderNamespacePaths(namespaces map[configs.NamespaceType]string) ([]string, error) {
	paths := []string{}
	nsTypes := []configs.NamespaceType{
		configs.NEWIPC,
		configs.NEWUTS,
		configs.NEWNET,
		configs.NEWPID,
		configs.NEWNS,
	}
	// join userns if the init process explicitly requires NEWUSER
	if c.config.Namespaces.Contains(configs.NEWUSER) {
		nsTypes = append(nsTypes, configs.NEWUSER)
	}
	for _, nsType := range nsTypes {
		if p, ok := namespaces[nsType]; ok && p != "" {
			// check if the requested namespace is supported
			if !configs.IsNamespaceSupported(nsType) {
				return nil, newSystemError(fmt.Errorf("namespace %s is not supported", nsType))
			}
			// only set to join this namespace if it exists
			if _, err := os.Lstat(p); err != nil {
				return nil, newSystemError(err)
			}
			// do not allow namespace path with comma as we use it to separate
			// the namespace paths
			if strings.ContainsRune(p, ',') {
				return nil, newSystemError(fmt.Errorf("invalid path %s", p))
			}
			paths = append(paths, p)
		}
	}
	return paths, nil
}

// bootstrapData encodes the necessary data in binary format as a io.Reader.
// Consumer can write the data to a bootstrap program such as one that uses
// nsenter package to bootstrap the container's init process correctly, i.e. with
// correct namespaces, uid/gid mapping etc.
//
// The binary format is:
// - 8 byte of uint64 total length of the key-value structure
// - for each key-value:
//	- 1 byte of uint8 for the length of key
//	- key content
//	- 4 byte of uint32 for the length of the value
//	- value
func (c *linuxContainer) bootstrapData(cmd *exec.Cmd, cloneFlags uintptr,
	nsMaps map[configs.NamespaceType]string, consolePath string) (io.Reader, error) {
	b := bytes.NewBuffer(nil)

	// write cloneFlags
	if err := encodeInt32(b, "clone_flags", uint32(cloneFlags)); err != nil {
		return nil, err
	}

	// write console path if we requires it
	if consolePath != "" {
		if err := encodeString(b, "console_path", consolePath); err != nil {
			return nil, err
		}
	}

	if len(nsMaps) > 0 {
		nsPaths, err := c.orderNamespacePaths(nsMaps)
		if err != nil {
			return nil, err
		}
		if err := encodeString(b, "ns_paths", strings.Join(nsPaths, ",")); err != nil {
			return nil, err
		}
	}

	// write namespace paths only when we are not joining an existing user ns
	_, joinExistingUser := nsMaps[configs.NEWUSER]
	if !joinExistingUser {
		// write uid mappings
		if len(c.config.UidMappings) > 0 {
			if err := encodeIDMapping(b, "uid_map", c.config.UidMappings); err != nil {
				return nil, err
			}
		}

		// write gid mappings
		if len(c.config.GidMappings) > 0 {
			if err := encodeIDMapping(b, "gid_map", c.config.GidMappings); err != nil {
				return nil, err
			}
		}
	}

	// prefix the total length and then write the data out
	data := bytes.NewBuffer(make([]byte, 0, b.Len()+8))
	if err := binary.Write(data, binary.BigEndian, uint64(b.Len())); err != nil {
		return nil, err
	}
	if _, err := io.Copy(data, b); err != nil {
		return nil, err
	}
	return data, nil
}

func encodeInt32(w io.Writer, name string, val uint32) error {
	if len(name) > 255 {
		return fmt.Errorf("%s is too long", name)
	}
	if err := binary.Write(w, binary.BigEndian, uint8(len(name))); err != nil {
		return err
	}
	if _, err := w.Write([]byte(name)); err != nil {
		return err
	}
	return binary.Write(w, binary.BigEndian, val)
}

func encodeString(w io.Writer, name, val string) error {
	if len(name) > 255 {
		return fmt.Errorf("%s is too long", name)
	}
	if err := binary.Write(w, binary.BigEndian, uint8(len(name))); err != nil {
		return err
	}
	if _, err := w.Write([]byte(name)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(val))); err != nil {
		return err
	}
	_, err := w.Write([]byte(val))
	return err
}

func encodeIDMapping(w io.Writer, name string, idMap []configs.IDMap) error {
	data := bytes.NewBuffer(nil)
	for _, im := range idMap {
		line := fmt.Sprintf("%d %d %d\n", im.ContainerID, im.HostID, im.Size)
		if _, err := data.WriteString(line); err != nil {
			return err
		}
	}
	return encodeString(w, name, data.String())
}
