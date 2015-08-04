
==========
spawn-supervise
=========
spawn-supervise的主要作用
1. 拉起多个worker进程并进行监控，worker进程异常退出后能被自动拉起;
2. 平滑的热升级。Worker进程通常有多个，在升级时，可以先部署新程序，然后批量kill掉老的workder进程，supervise 进程在收到子进程的退出信号后，会重新拉起worker进程，而新拉起的worker进程已经是更新后的进程。这样新老进程并存，达到了无缝热升级的效果。

Usage
=====
```
spawn-supervise -u user -p port -F fork_number -- application_main arguments
fork_number:指要fork多少个worker进程
port: 所有的worker进程共同监听一个端口，各自accept数据包。
application_main： 用户的二进制程序， 一般包含一个while的死循环，并阻塞在epoll_wait或其他事件上面。
arguments： 用户程序的参数
另外， 可以使用scripts/service_template将appliaction做成系统服务， 从而可以这样使用：
service application start|stop|status|restart
```

Features
--------
- binds to IPv4/IPv6 and Unix domain sockets
- supports privilege separation: chmod/chown socket, drop to uid/gid
- supports chroot
- supports supervise

Build
=====

If ./configure is missing, run ./autogen.sh.

  ./configure<br/>
  make<br/>
  make install<br/>

Alternatively you can use the cmake build system (may not work
on every platform):

  cmake .<br/>
  make   <br/>
  make install<br/>



