<h1 align=center><code>☠️ Death</code></h1>

**Death** is a virus targeting ELF64 binaries.   
**⚠️ Do not run this on your system. You have been warned.**

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

---

## ⚠️ Disclaimer

This project is **for educational purposes only**.  
Use responsibly — or not at all.

---
