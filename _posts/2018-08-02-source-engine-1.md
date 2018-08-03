---
layout:     post
title:      Exploiting the Source Engine (Part 1)
date:       2018-08-02
summary: An introduction into the engine.
categories: source-engine exploitation reverse-engineering
typora-copy-images-to: ../assets
typora-root-url: ../../gbps.github.io
---

## Introduction

It's been a long time coming, but here's my first post on a series about finding and exploiting bugs in [Valve Software's Source Engine](https://en.wikipedia.org/wiki/Source_(game_engine)). I was first introduced to it through the sandbox game [Garry's Mod](https://store.steampowered.com/app/4000/Garrys_Mod/) in 2010, which introduced me to the field of reverse engineering and paved the way for my favorite hobby, my education, and my eventual employment.

I took a long hiatus from working with the Source Engine when I went to college and got involved obsessed with playing [CTF competitions](https://ctftime.org/ctf-wtf/), a type of competition where participants solve challenges that mimic real-world reverse engineering and exploitation tasks. One day, I saw a post made about a TF2 RCE proof-of-concept released against the engine. To be honest, the bug and the exploit was very simple, and nothing more difficult than some of the intermediate challenges one would find in a good CTF. With that knowledge under my belt, I decided to prove myself and come back to the Source Engine with the goal of finding a true [Remote Code Execution](https://en.wikipedia.org/wiki/Arbitrary_code_execution) (RCE). 

As it turns out, this was around the time that [Valve released their Bug Bounty program through HackerOne](https://hackerone.com/valve), where they boasted a bounty range of **\$1,000 - \$25,000** for these kind of bugs. With a bit of luck, [I successfully found and wrote a proof-of-concept for a critical Server to Client RCE bug](https://hackerone.com/gbps), and was given a generous bounty of **$15,000** from Valve. Everything in this series is dedicated to information I've learned along the way about the engine.

> NOTE: As of writing, the vulnerability has not been publicly disclosed. I will be doing a writeup of the bug and exploit chain if/when it goes public.

| ![image-20180802185147009](/assets/image-20180802185147009.png) |
| :----------------------------------------------------------: |
| *Source games Dota 2, CS:GO, and TF2 continue to hold top active player counts on Steam*. |

## The Source Engine

The Source Engine is a third generation derivative of the famous [Quake Engine](https://en.wikipedia.org/wiki/Quake_engine) from 1999 and the Valve's own [GoldSrc](https://en.wikipedia.org/wiki/GoldSrc) engine (the HL1 engine). The engine itself has been used to create some of the most famous FPS game series' in history, including Half-Life, Team Fortress, Portal, and Counter Strike. 

### Timeline:

* 1998 - Valve showcases **GoldSrc**, a heavily modified Quake engine.
* 2004 - Valve releases the **Source Engine** based on GoldSrc.
* 2007 - The source code to the [**Source Engine is leaked**](https://github.com/VSES/SourceEngine2007).
* 2012 - CS:GO is released, and with it, **"Source 1.5"** begins development.
* 2013 - Valve releases the [**public 2013 SDK for the TF2/CS:S engine**](https://github.com/ValveSoftware/source-sdk-2013) containing most of the code necessary to write games for the engine.
* 2015 - The "Reborn" update for Dota 2 brings the first **Source 2** game to market.
* 2018 - Valve opens their HackerOne program to the public.

### The Code:

The first thing that I didn't truly appreciate about this engine (and other engines in general) is how *large* it is. The engine is gigantic, featuring millions of lines of C++ code to develop, render, and run games of all types (but mostly first-person games).

The code itself is old and unmaintained. Most of the code was very obviously rushed out to meet deadlines, and honestly it is a huge surprise that the engine even functions at all. This is not unique to Valve, and is very typical in the game development world. 

Assets such as models, particles, and maps are all built and run using custom file formats developed by Valve or extended from Quake (yes, file format parsers from 1999). There are still usages of obviously unsafe functions such as `strcpy` and `sprintf`, and in general the engine itself has a history of "add, add, add" and very little maintenance.

A lot of the C++ classes included in the engine are straight up dead code. Big features  were designed and developed, yet only used for very small parts of the engine. The 2013 SDK tools themselves still have difficulty building valid files for their current engine versions of the engine. Classes derive from anywhere from one to nine different base classes, and tend to feature a never-ending maze of abstractions on abstractions. All in all, the engine is due for a legacy code rewrite that will likely never happen.

### Intro to Source Games:

Source Engine games consists of two separate parts, the engine and the game. 

The engine consists of all of the typical game engine features like rendering, networking, and the asset loaders for models and materials, and the physics engine. Wen I refer to the *Source Engine*, I am referring to this part of the game. The bulk of the engine's code is found in `engine.dll`, which is found in the path `/bin/engine.dll` from the game's root. This same base code is used in some manner across all SE games, and is typically utilized by 3rd party game developers in its pre-compiled form. The code for the Source Engine was [leaked](https://github.com/VSES/SourceEngine2007) (luckily) as part of the 2007 Valve leak, and this leak is all the code that is available to the public for the engine.

The second part, the *game*, consists of two main parts, `client.dll` and `server.dll`. These binaries contain the compiled game that will use the engine. Both of these dlls will utilize `engine.dll` heavily in order to function. Inside of `client.dll`, you will find the code responsible for the GUI subsystem (named [VGUI](https://developer.valvesoftware.com/wiki/VGUI_Documentation)) of the game and the clientside logic of the actual game itself. Inside of `server.dll`, you will find all of the code to communicate the game's serverside logic to the remote player's `client.dll`. 

Both the server and client have shared code that defines the entities of the game and variables that will be synchronized. Shared code is compiled directly into each binary, but some C macro design ensures that only the server parts compile to `server.dll`, and vice-versa. The `engine.dll` entity system will synchronize the server's simulation of the game, and the client's dll will take these simulations and display them to the player through the `engine.dll` renderer. 

Lastly, a big feature of all Source games that was taken and evolved from the Quake engine is the [ConVar](https://developer.valvesoftware.com/wiki/Developer_Console) system. This system defines a series of variables and commands that are executed on an internal command line, very similar to a cmd.exe or /bin/sh shell. The difference is that, instead of executing new processes, these commands will run functions on either the client or server depending on where its run. The engine defines some low-level convars found on both the server and client, while the game dlls add more on top of that depending on the game dll that's running.

* A Console Variable ([ConVar](https://developer.valvesoftware.com/wiki/ConVar)) takes the form of `<name> <value>`, where the value can be numerical or string based. Typically used for configuration, certain special ConVars will be synchronized. The server can always request the value of a client's ConVar. Example: `sv_cheats 1` sets the ConVar `sv_cheats` to `1`, which enables cheats.
* A Console Command ([ConCommand](https://developer.valvesoftware.com/wiki/ConCommand)) takes the form of `<name> <arg0> <arg1> …`, and defines a command with a backing C++ function that can be run from the developer console. Sometimes, it is used by the game or the engine to run remote functions (client -> server, server -> client). Example: `changelevel de_dust` executes the command `changelevel` with the argument `de_dust`, which changes the current map when run on the server console.

*This is just an intro, more on all of this to follow in future posts.*

### The Bugs:

All of this old code and custom formats is *fantastic* for a bug hunter. In 2018, all that's truly necessary to perform a full chain RCE is a good memory corruption bug to take control and an information leak to bypass ASLR. Typically, the former is the most difficult part of bug hunting in modern software, but later you will see that, for the SE, it is actually the latter.

Here is an overview of the Windows binaries:

* **32-bit binaries**
* **NX** - Enabled
* **Full ASLR** - Enabled (recently)
* **Stack Cookies** - <u>Disabled</u> (in the cases it matters)

If you're an exploit developer, you would probably find the lack of stack cookies in a game engine with millions of players to be a very shocking discovery. This is a vital shortcoming of the already aging engine, and is essentially unheard of in modern Windows binaries. Valve is well aware of this protection's existence, and has chosen time and time again not to enable it. I have some speculation as to why this is not enabled (most likely performance or build breaking issues), but regardless, there is a huge point to make: **Any controllable stack overflow can overwrite the instruction pointer and divert code execution.** 

Considering how much the stack is used in this engine, this is a huge benefit to bug hunters. One simple out-of-bounds (OOB) string copy, such as a call to `strcpy`, will result in swift compromise of the instruction pointer straight into RCE. My first bug, unsurprisingly, is a stack overflow bug, not much different than you would find in a beginner level CTF challenge. But, unlike the CTF, its implications of a full client machine compromise in a series of games with a huge player base leads to the large payout.

### Hunting:

When hunting for these bugs, I chose to take a slightly more difficult path of only performing *manual code auditing* on the publicly available engine code. What this allows me to do is both search for potentially useful bugs and also learn the engine's internals along the way. While it might be enticing for me to just fuzz a file format and get lots of crashes, fuzzing tends to find surface level bugs that everyone's finding, and never those really deep, interesting bugs that no one is finding.

As I said previously, the codebase for this engine is gigantic. You should take advantage of all of the tools available to you when searching. My preferred toolset is this:

* Following code structure and searches using **Visual Studio with Resharper++**.
* **Cmder (with grep)** to search for patterns.
* **IDA Pro** to prove the existence of the bug in the newest build.
* **WinDbg and x64dbg** to attach to the game and try to trigger the bug.
* **Sourcemod extensions** to modify the server for proof-of-concepts

With these tools, my general "process" for bug hunting is this:

1. Find some section of the client code I feel is exploitable and want to look into more closely

2. Start reading code. I'll read for hours until I come across what I think is a possible exploitable bug. 

3. From there, I will open up IDA Pro and locate the function I think is exploitable, then compare its current code with the old, public code I have available.

4. If it still appears to be exploitable, I will try to find some method to trigger the exploitable function from in-game. This turns out to be one of the hardest parts of the process, because finding a triggerable path to that function is a very difficult task given the size of the engine. Sometimes, the server just can't trigger the bug remotely. Some familiarity with the engine goes a *long* way here. 

5. Lastly, I will write [Sourcemod](https://github.com/alliedmodders/sourcemod) plugins that will help me trigger it from a game server to the client, hoping to finally prove the existence of the bug and the exploitability in a proof-of-concept.


## Next Time

Next post, I will go more in-depth into the codebase of the Engine and explain the entity and networking system that the Engine utilizes to run the game itself. Also, I will begin introducing some of the techniques I used to write the exploits, including the ASLR and NX bypass. There's a **whole** lot more to talk about, and this post barely scratches the service. At the moment, I'm in the process of working on a new undisclosed bug in the engine. Hoping to turn this one into another big payout. Wish me luck!



— Gbps