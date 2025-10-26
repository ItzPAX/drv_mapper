## Driver Mapper
Map a driver into a signed section of an rwx dll that is loaded in your process.

The driver is only visible from your process context so any calls to the driver outside your process will bsod your system.

You can't create a system thread even in the process's context so the preferred way of communicating is by hijacking an existing IOCTL. This approach will however crash your system if any other process tries to use the hijacked IOCTL.

Here's an example picture ![Mapped Driver Image](https://i.imgur.com/KySpZck.jpeg "Mapped Driver")

Detailed writeup and discussion [Unknowncheats](https://www.unknowncheats.me/forum/anti-cheat-bypass/722956-map-driver-rwx-dll-section.html)
