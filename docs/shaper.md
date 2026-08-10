# Shaper

 **Task.** Even with correct TLS fingerprinting and hidden authentication, DPI (Deep Packet Inspection) can detect a tunnel based on traffic flow characteristics: the traffic of restricted resources often appears as a nearly uniform stream or a burst-pause-burst pattern. Shaper allows you to change the shape of the traffic by creating a list of randomly switched phases (if more than one is defined) with speed limits. You can define just a single phase, in which case the shaper acts as a simple limiter.

 **How it works** 

* When `shaper` is enabled, the client launches a local **phase engine** .
* An infinite loop randomly selects a phase (different from the previous one if the number of phases > 1) and its duration, then applies limits via a token-bucket algorithm.

 **Phases:** 

| Phase        | Duration | ↓ Mbps | ↑ Mbps | What it simulates                      |
| ----------- | ------------ | ------ | ------ | ---------------------------------- |
| `idle` | 1–2 sec      | 0.0    | 0.0    | Inactivity                            |
| `page_load` | 1–2 sec      | 12.0   | 0.8    | Loading HTML / CSS / JS / fonts |
| `images` | 1–2 sec      | 6.0    | 0.1    | Loading galleries / previews          |
| `api_call` | 1–2 sec      | 0.4    | 0.3    | Short XHR / fetch requests        |
| `upload` | 1–2 sec      | 0.3    | 4.0    | Uploading files or photos  |

There is no deterministic cycle: each subsequent phase is chosen randomly, and the duration is within a specified range. This makes the pattern irregular.

 **Throttling.** Implemented using a built-in token-bucket (no external dependencies). A phase with 0 Mbps completely blocks writing. shapedWriter/shapedReader wrap the I/O operations into the throttle.

 **Example.** 

This is approximately what the overall traffic shape of YouTube looks like when watching a video (1080p 60fps). It is a quite distinctive pattern.

![Screen1](./screens/youtube.png)

And here is how the traffic shape can be modified using Shaper. It looks more like a file download.

![Screen2](./screens/youtube_shaped.png)
