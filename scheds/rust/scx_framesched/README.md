# scx_framesched

A scheduler designed specifically to optimize for interactive (typically
gaming) workloads, and battery life. This scheduler expects the user to
provide QoS input on threads and cgroups in the system in order to make
scheduling decisions.


## Overview

A scheduler designed for seamless, interactive experiences, and maximal battery
life. scx_framesched is designed to be robust to background work, and
prioritizes work that's critical for interactivity, while also trying to
maximize the battery life of a mobile device.
