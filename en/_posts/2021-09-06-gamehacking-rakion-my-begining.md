---
layout: post
title: "Gamehacking: Rakion, the begining"
author: "Nox"
description: "My begining in the gamehacking and reversing attacking Rakion"
keywords: "gamehacking, rakion, c++, reversing"
date: 2021-06-09 00:00:00 -0500
categories: reversing
lang: en
lang-ref: gamehacking-rakion-my-begining
---

# Some words of my past

When I started in reverse engineering I was in high-school in Peru and with my frieds I played DotA and Rakion. One day a dude started to use a cheat (at that time we called it "hack" :P), after asking him many times he told me where he had downloaded it. 

At that moment I started in the world reversing, it was very hard to me because I didn't know anything about programming, reverse engineer, assembly, even how to use google. Furthermore, starting in the gamehacking world is very hard because there is money involved. 

In the forum where I downloaded the cheat, one day a guy shared a really good post about what I'm going to name, "My first cheat". He said it was their research, but then other people denied it, saying it was someone else's work that he had appropriated. While there was a fight of egos in that forum, for me it was the beginning of my world in reverse engineering.

Several years have passed and I want to technically tell you how I started and what cheats for Rakion I did.

<!--more-->

## Introduction

The main goal to start cheating any MMORPG or similar games is to find the entity player, because usually it will be found inside a bigger structure and/or reference to another ones with game player information. 

Possibly there will exist at least two entity player (or only one), entity in-lobby player and entity in-game player, of course it depends on the game design. In the entity lobby player we could found player armor (such as helm, gauntlet, cuirass, primary and secondary weapon, rings, etc), summoned creatures and their information (such as the kind and level), inventory, gold (it's very likely that we cannot modify it because is server-side information), stats, etc. And for the entity in-game player we could found, the character position axis according to the render game model, virtual camera system (such as camera display spectrum of the character, observer camera, graphical perspective camera, etc), type of character, [etc][1].

[Rakion][2] is an 3D MMORPG computer game that has two main DLLs, the first one is `entitiesmp.dll` and the second one is `engine.dll`. `entitiesmp.dll`  has the implementation of character interaction such as its armor, health points (in this game that info is client-side), cell points (points required for cell creature summoning), attacks , etc.  `engine.dll` has the implementation of game capabilities or character information such as position axis, enemies position axis, character encryption information, etc. Furthermore, Rakion has a file called `DataSetup.xfs` where there is game information such as [stage map][3], items, cell creatures, etc, and historically it was zlib compressed, `DataSetup.xfs` is read when the game is loaded therefore, some malicious modification was reflected in the game (some information is read in runtime such as stage configuration), now (I think) it is encrypted on disk but unencrypted in memory ;).

## [My first cheat](#my-first-cheat)
An "easy cheat" to write in this first blogpost (even was my first cheat ever) is about summoning a [cell creature][4] for another one, also know as Cell2Cell. `entitiesmp.dll` export objects of `CNpc[\w+]_DLLClass`, in other words the information of cell creatures are exported and its size is 84 bytes.

```
.data:355F0FD0 CNpcNak4_DLLClass dd offset unk_356149AC
.data:355F0FD0                                         ; DATA XREF: .rdata:off_35588D28↑o
.data:355F0FD4                 align 8
.data:355F0FD8                 dd offset unk_356149B0
.data:355F0FDC                 align 10h
.data:355F0FE0                 dd offset unk_355F0FC0
.data:355F0FE4                 db    1
.data:355F0FE5                 db    0
.data:355F0FE6                 db    0
.data:355F0FE7                 db    0
.data:355F0FE8                 dd offset unk_356149D0
.data:355F0FEC                 db    1
.data:355F0FED                 db    0
.data:355F0FEE                 db    0
.data:355F0FEF                 db    0
.data:355F0FF0                 dd offset aNpcnak4      ; "NpcNak4"
.data:355F0FF4                 dd offset Buffer
.data:355F0FF8                 db  73h ; s
.data:355F0FF9                 db    4
.data:355F0FFA                 db    0
.data:355F0FFB                 db    0
.data:355F0FFC                 dd offset CNpcNakBase_DLLClass
.data:355F1000                 dd offset sub_351D86D0
.data:355F1004                 dd offset nullsub_1804
.data:355F1008                 dd offset nullsub_1805
.data:355F100C                 dd offset nullsub_1806
.data:355F1010                 dd offset nullsub_1807
.data:355F1014                 dd offset nullsub_1808
.data:355F1018                 dd offset nullsub_1809
.data:355F101C                 dd offset nullsub_1810
.data:355F1020 ; public class CNpcNak4 /* mdisp:0 */ :
.data:355F1020 ;   public class CNpcNakBase /* mdisp:0 */ :
.data:355F1020 ;     public class CNpcBase /* mdisp:0 */ :
.data:355F1020 ;       public class CMovableModelEntity /* mdisp:0 */ :
.data:355F1020 ;         public class CMovableEntity /* mdisp:0 */ :
.data:355F1020 ;           public class CRationalEntity /* mdisp:0 */ :
.data:355F1020 ;             public class CLiveEntity /* mdisp:0 */ :
.data:355F1020 ;               public class CEntity /* mdisp:0 */
.data:355F1020 ; class CNpcNak4 `RTTI Type Descriptor'
.data:355F1020 ??_R0?AVCNpcNak4@@@8 dd offset ??_7type_info@@6B@
.data:355F1020                                         ; DATA XREF: .rdata:354F46A8↑o
.data:355F1020                                         ; .rdata:CNpcNak4::`RTTI Base Class Descriptor at (0,-1,0,64)'↑o
.data:355F1020                                         ; reference to RTTI's vftable
.data:355F1024                 dd 0                    ; internal runtime reference
.data:355F1028 aAvcnpcnak4     db '.?AVCNpcNak4@@',0   ; type descriptor name
```
For example `CNpcNak4_DLLClass` could be overwrite with the information of another cell creature object, so when it is summoned the creature will be the another one. 

Basically is do:
```c
PBYTE nak4_addr = (PBYTE)GetProcAddress(GetModuleHandleA("entitiesmp.dll"), "CNpcNak4_DLLClass");
PBYTE taurus1_addr = (PBYTE)GetProcAddress(GetModuleHandleA("entitiesmp.dll"), "CNpcTaurus1_DLLClass");
memcpy(nak4_addr, taurus1_addr, 84);
```
Nak4 is white nak, and when it is summoned three naks appear. It is why three Taurus are summoned.

<div align="center"><iframe width="560" height="315" src="https://www.youtube.com/embed/r1qFL2EPQRo" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe></div>

<br>

## The entities
In this game, there are two entities, in-lobby and in-game (at least I call it that way). Of course the key for many cheats is to get its addresses, because we can modify and abuse many things such as cell creatures, stats, type of attacks, position axis, etc.

[**The entitiy in-game**](#entity-in-game), has information of the character in-game, and in this we can abuse in the health point (HP), armor point (AP), cell point (CP), caos points, potions (pots [see the number 6][1]), position axis, etc. 

To get the entity in-game player address I should call two functions `entitiesmp!CPlayer::GetLocalPlayer` and `engine!FieldInfo::GetLocalPlayer`.

```c
FieldInfo& CPlayer::GetFieldInfo()
CEntity& FieldInfo::GetLocalPlayer()
```
There is a function that shows us how I should call both, `entitiesmp! 
CPlayer::GetLocalPlayer`.

```c
CEntity& CPlayer::GetLocalPlayer()
{
  FieldInfo objFieldInfo = this->GetFieldInfo();
  return objFieldInfo->GetLocalPlayer();
}
```
In assembler:
```asm
invoke GetModuleHandle, addr entitiesmp
invoke GetProcAddress, eax, addr GetFieldInfo
cmp eax,NULL
jz end
call eax
push eax

invoke GetModuleHandle, addr engine
invoke GetProcAddress, eax, addr GetLocalPlayer
pop ecx
call eax
; eax: entity in-game address
```

This entity can only be obtained in game, and its address will always change for each play.

[**The entitiy in-lobby**](#entity-in-lobby), is totally different than entity in-game, because the address does not change and has information about the items and stats of the character, etc. When I was 15 years old, that address can be obtained from `entitiesmp!GetSelectLevelInfo()` function.

```c
// IDA Pro 6.x decompiler
struct _s_stage *__cdecl GetSelectLevelInfo()
{
  int v0; // edx@1
  int v1; // ecx@1
  int v2; // eax@1

  v2 = (*(int (**)(void))(*(_DWORD *)dword_354B7FC4 + 12))();
  if ( IsBattleMap(*(_BYTE *)(v2 + 443)) )
    v1 = 1;
  return GetLevelInfo(, *(_BYTE *)(v0 + 442));
}
```

The address of entity in-lobby is `0x354B7FC4`, but currently the  `entitiesmp!GetSelectLevelInfo()`  implemention changed and and it never shows the address anymore.

```c
struct _s_stage *__cdecl GetSelectLevelInfo()
{
  FieldInfo objGFieldInfo = GetGlobalFieldInfo();
  int game_type = objGFieldInfo->GetGameType();
  if ( IsBattleMap(game_type) )
    game_type = 1;
  return (struct _s_stage *)GetLevelInfo(game_type, objGFieldInfo->LevelInfo));
}
```
 Of course in the nexts blogposts I will explain how we can get it ;).

For now, here I leave just a small example of what can we do getting the entities.

<div align="center"><iframe width="560" height="315" src="https://www.youtube.com/embed/RCyeRa_HWCg" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe></div>

<br>

> Written by [**Nox**][5]

Follow us on our twitter account [@rop-la][rop-twitter], our public Github repositories [RoP-LA][rop-github] and [Youtube Channel][rop-youtube].

[rop-web]: https://www.rop.la
[rop-twitter]: https://twitter.com/rop_la
[rop-github]: https://github.com/rop-la/
[rop-youtube]: https://www.youtube.com/channel/UCg01TfhxLro71ppULtIBAjw


[1]:http://rakion.softnyx.net/GameInfo/BeginnersGuide/Interface.aspx
[2]:https://rakion.fandom.com/wiki/Rakion:_Chaos_Force
[3]:https://rakion.fandom.com/wiki/Stage_Maps
[4]:https://rakion.fandom.com/wiki/Cell_Creatures
[5]:https://twitter.com/MrNox_
