# Another Tunnel Shell (ATSH)
> Written in C with fun :D
## Why ATSH When we have NotATunnel and OpenSSH?
just for teaching. but i will use atsh for my servers and etc
## NotATunnel is your project! why you do the fork?
Rust. i hate it i love it but C looks better and also i wanna do monolith shell not a client on another repo and server on another
## Will it cross-platform?
Maybe only for Linux and BSD based systems

# project model

``` mermaid
graph LR
A[NotATunnel]
A --> B[Fork + Rewrite] --> D[Client]
NotAProto --> B --> J[Using NotAProto] --> C

B --> E[Server]
D --> C
E --> C[ATSH]
```
