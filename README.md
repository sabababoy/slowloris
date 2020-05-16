# slowloris
Important: The main idea of the project was not to attack something/someone, but study the operation of networks, implement basiс TCP stack and working with assync libs.
Tested on sites that run on port 80 (It works, The host stops accepting requests)

This repository, the second attempt to implement a script to conduct slowloris attacks. https://github.com/sabababoy/http-slowloris
The first project is working. It can stop the server on + - 500 connections, which is very small. Also, he had drawbacks of which the two most important ones were incorrect implementation and, as a result, speed. Having studied everything in more detail, I realized that the main problem is that the connection is established through the socket (AF_INET, AF_STREAM), leaving the entire implementation to the kernel connection. The socket.connect() function blocks I/O and makes it impossible to send the next packet until the answer to the first comes. Because of this, it was decided to use raw sockets and establish all connections manually. Sending a packet with the SYN falcon separately, separately accept the response, send ACKs and requests (implement the TCP stack manually). Using methods of asynchronous programming, you can achieve acceleration of work at times. At the moment, to use asynchronous programming, it was decided to use the asyncio library.

# At the moment, work is still underway, the program is not fully implemented, but it works with port number 80.

All development details are in the development log.
