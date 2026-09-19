<p align="center">
  <img src="assets/images/the-young-girl-and-death.webp" alt="The Young Girl and Death by Marianne Stokes" width="500">
</p>

<h1 align="center"><code>Death</code></h1>

**Death** is a virus targeting ELF64 binaries.   
**⚠️ Do not run this on your system. You have been warned.**

---

## Demo

▶️ [Watch the demo](assets/demo.mp4)

---

##  Architecture

This virus is structured in **four distinct layers**, each more complex and destructive than the last:

- **Famine**  
  The initial infection stage. A self-replicating virus that targets ELF64 binaries.

- **Pestilence**  
  Polymorphic part, the infected binaries are encrypted and there is anti-debugging techniques.

- **War**  
  This stage introduces **metamorphic** techniques, rewriting its signature each generation.

- **Death**  
  The final form. Fully metamorphic: it can change its code structure.

---

##  Entry Point

The execution starts in `famine.c`, where the infection begins.

The virus infects `/tmp/test` and `/tmp/test2`

---

##  Reverse shell

A hidden **daemon** acts as a stealthy **backdoor** and provides a **remote shell**.

- If an infected binary (for example, `ls`) is executed, it can **automatically start the daemon** if it is not already running.
- The daemon silently runs in the background, trying to connect to the server.
- Upon connection, it can spawn a fully interactive **reverse shell**, allowing the attacker to execute arbitrary commands on the compromised host.

This turns an infected system into a fully controlled machine, without the user's knowledge.

### Local reverse-shell test

The reverse shell is configured in `shell.c` to connect only to
`127.0.0.1:9001`. After starting `Death` inside the disposable container, open
a second shell in the same container and start a local listener before
triggering the reverse shell:

```sh
nc -lvnp 9001
```

Keep this test entirely inside the isolated container. Do not publish port
`9001`, change the listener address, or expose it to the host or another
network.

---

## Build environment

The program was compiled and tested with:

- GCC 12.2.0 (`Debian 12.2.0-14+deb12u1`)
- Debian 12
- x86_64

---

## Docker environment

> [!CAUTION]
> This project manipulates and infects ELF64 binaries. Build and test it only
> inside a disposable Docker environment. Never execute `Death` or an infected
> binary directly on the host, on a production machine, or on a system
> containing important data.

The Docker image uses Debian 12 and provides GCC 12.2.0, Make, GDB, Strace,
NASM, Zsh and Oh My Zsh. The repository is mounted at `/workspace` inside the
container.

### Requirements

- Docker Engine
- An x86_64 host, or an environment capable of running x86_64 containers

### Start the environment

From the repository root:

```sh
make docker-up
```

Once the container is running, open a shell inside it:

```sh
make docker-exec
```

The shell opens directly in `/workspace`.

### Build and test

Inside the container, the project can be compiled with the `FUN` definition:

```sh
make def=-DFUN
```

> [!WARNING]
> `FUN` is not a harmless test mode. As defined in `famine.c`, it changes the
> primary infection path from `/tmp/test` to `/bin`. The program then walks
> that directory recursively and attempts to infect eligible ELF64 binaries.
> The secondary path remains `/tmp/test2`. Use this build only inside the
> disposable container and never run it on the host.

To clean and rebuild it with the same option:

```sh
make re def=-DFUN
```

Then execute the resulting `Death` binary inside the disposable container and
have fun. Keep all test files inside the container, particularly in `/tmp`, and
never run the executable directly on the host.

---

## ⚠️ Disclaimer

This project is **for educational purposes only**.  
Use responsibly — or not at all.

---
