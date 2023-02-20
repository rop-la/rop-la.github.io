---
layout: post
title: "Rakion: Entities and editing cell creatures"
author: "Nox"
description: "Will show how to get the player in-lobby and in game entities and how to edit cell creatures"
date: 2023-02-17 00:00:00 -0500
categories: reversing
keywords: "rakion, c++, gamehacking"
lang: en
lang-ref: rakion-entities-editing-cell-creatures
---

Part I: [Gamehacking: Rakion, the begining]({{site.baseurl}}{% link en/_posts/2021-09-06-gamehacking-rakion-my-begining.md %})
<br>
Parte II: [Rakion: Entities and editing cell creatures]({{site.baseurl}}{% link en/_posts/2023-02-17-rakion-entities-editing-cell-creatures.md %})

A principle in the gamehacking is that if a value changed we can scan the memory, get its address, and modify the value arbitrarily. For example, if player's health has 64 or 0x100 as max value and receives one of damage, that value will decrease one, allowing us to scan the memory, obtain a group of results, and on that group keep scanning everytime that health value is modified to reduce the result group to a few addresses until getting the health player address with the purpose of modifying that value at our whim.

Of course there are variants, and it isn't the only way, but it's a good first step.

<!--more-->

In this game existing cell's creatures are allies, and can be summoned by consuming cell points (CP). That cell's creatures can be equipped in the lobby, and that action set a value in memory (a byte is written) or removed (a null byte is written), that cell's creature value will be named in this blogpost as cell's creature ID. 


## Editing cell creatures in-lobby {#editing-cc-in-lobby}
There are two ways to get the cell's creature ID address in the lobby, scan an unknow value to get the group of results, remove the cell creature (that value will change to 0), and scan over that group, then repeat until getting few addresses. The other way is by knowing the value of cell creature in memory previously, this way is possible because in past, Rakion had a resource file called `Datasetup.xfs` in plain text where we found cell's creature IDs, items stats, stage properties (the stages also are called as quests in other games), etc.

In the following video we can see how to get the cell creature address in lobby using the first method.

<div align="center"><iframe width="560" height="315" src="https://www.youtube.com/embed/9MBFSEyKc0Y" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen="">
</iframe><br>
<em>Searching and editing a cell creatures in-lobby (2015-dic version)</em>
</div>
<br>
n the video my player is *Xeen* and, to reduce the results group, I started looking if my player name is close, because it is usual that entity player structure has value of items, stats, and related information like the player's name.

And we have our first cheat :D. Anyway, if you restart the game, the cell's creature ID address will change. How we can fix it? Check [**Entity in-lobby**](#entity-in-lobby) section.

## Entities

A player entity is a structure that contains player's information (pointers, properties, names, etc). In this game, we can say that already exist two entities, in-game, and in-lobby, and the last one probably wasn't created as a player entity but due the posibility to modify some player's items in lobby we'll call it in that way for didactic purpose.

### Entity in-lobby {#entity-in-lobby}
Trying to figure out a method to get the cell's creature ID address, I notized that there are some hardcoded adresss in `entitiesmp.dll`. Then, I looked up if those addresses were lower than cell's creature ID address, and if that lower addresses have a constant delta toward cell's creature ID address. 

You can see the hardcoded address implementation in differents versions of `entitiesmp.dll`.

2010-dic:
```cpp
// IDA Pro 6.x decompiler 
int __cdecl CPlayer__EndGame()
{
  return (*(int (**)(void))(*(_DWORD *)dword_354B7FC4 + 284))();
}
```

2012-may:
```cpp
void __thiscall CPlayer::EndGame(CPlayer *this)
{
  (*(void (__thiscall **)(_DWORD))(**(_DWORD **)_pRakionWorldNet + 256))(*(_DWORD *)_pRakionWorldNet);
}
```

2015-dic:
```cpp
void __thiscall CPlayer::EndGame(CPlayer *this) 
{ 
 (*(void (__thiscall **)(int))(*(_DWORD *)dword_356647B4 + 280))(dword_356647B4); 
}
```

Let's see it on CheatEngine:

<div align="center"><iframe width="560" height="315" src="https://www.youtube.com/embed/dUgNcRh0oDw" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen="">
</iframe><br>
<em>Editing cell creatures in-lobby by CE (2012-may version)</em>
</div>
<br>
Indeed, 2015 version (and probably later), the cell creature level is found 2 bytes after the ID.

## Entity in-game
There is a function that return a CPlayer object called: `class CPlayer *__thiscall CPlayer::GetLocalPlayer(CPlayer *this)` from `entitiesmp.dll`. It's important to mention that this function returns the current active CPlayer object, it means that the function will return an object when your character is in-game.

```cpp
class CPlayer *__thiscall CPlayer::GetLocalPlayer(CPlayer *this) 
{ 
 FieldInfo *FieldInfo; // eax 
 FieldInfo = CPlayer::GetFieldInfo(this); 
 return FieldInfo::GetLocalPlayer(FieldInfo); 
}
```

For test purposes, I had to figure out a way to get the CPlayer's object address every time I need it. Then, I made the following CE script but there is an issue, when I disabled it the game crashes that's why I wrote a infinite loop :P. So, I only added the symbol `objCPlayer` in CE Table to get the CPlayer object address.

```nasm
alloc(mythread, 512)
createthread(mythread)

alloc(objFieldInfo, 4)
alloc(objCPlayer, 4)

[ENABLE]

registerSymbol(objFieldInfo)
registerSymbol(objCPlayer)
mythread:

  xor eax, eax
  call CPlayer::GetFieldInfo
  mov [objFieldInfo], eax

get_entity:
  mov ecx, [objFieldInfo]
  call FieldInfo::GetLocalPlayer
  test eax, eax
  mov [objCPlayer], eax

  push 2000
  call kernel32.Sleep
  jmp get_entity


  ret //terminates thread

[DISABLE]
unregisterSymbol(objFieldInfo)
dealloc(objFieldInfo)
dealloc(mythread)
```

Some days before, I found out a variable which is initialized with the CPlayer object address every time. In 2012-may version `entitiesmp.dll + 0x4b42f0`, and 2015-dic version `entitiesmp.dll + 00xx87CB28`

## Editing cell's creatures in-game
As [**Editing cell creatures in-game**](#editing-cc-in-lobby) section explained, we need to find out the exact address in-game where cell's creature ID is located.

In 2015-dic version, there is a function called `void __thiscall CPlayer::SpawnNPC_n(CPlayer *this, struct CellInfo *a2, struct CPlayer *a3, int a4)` used when a cell's creature is summoned, but there isn't any direct crossreference because it's accessed from CPlayer's vftable. That function calls to `sub_35158F20(a2, a3, i);`

```cpp
void __cdecl sub_35158F20(int *a1, int a2, int a3)
{
  // [...]

  GlobalFieldInfo = GetGlobalFieldInfo();
  if ( FieldInfo::IsRoundState(GlobalFieldInfo, 1) )
  {
    if ( *((_BYTE *)GetGlobalFieldInfo() + 313) != 1
      && *(_BYTE *)(*(unsigned __int8 *)(*((_DWORD *)_pNetwork + 9) + 0x294C) + *((_DWORD *)_pNetwork + 9) + 0x294D) < 9u )
    {
      CPlacement3D::CPlacement3D((CPlacement3D *)v21);
      v4 = (int *)sub_35158C30(v20, a2, a3);
      v21[0] = *v4;
      v21[1] = v4[1];
      v21[2] = v4[2];
      v21[3] = v4[3];
      v21[4] = v4[4];
      v21[5] = v4[5];
      CTString::CTString((CTString *)&v18, "pwoCurrentWorld");
      v22 = 0;
      INDEX = (CWorld *)CShell::GetINDEX(_pShell, (const struct CTString *)&v18);
      v22 = -1;
      CTString::~CTString(&v18);
      CreatureStr = (const struct CTString *)GetCreatureStr(v17, a1[1]);
      // [...]
```

In 2012-may version, `CPlayer::SpawnNPC_n` doesn't exist, but `sub_35158F20(a2, a3, i);`(2015-dic version) does exist, and is in `void __cdecl sub_350E3260(int *a1, int a2)` (2012-may version). Almost, there is a crossreference from `CPlayer::ButtonsActions`. With a quick analize I can conclude both functions have as first argument `struct CellInfo*` type, and the second is `struct CPlayer*` type.

Reviewing the function caller `CPlayer::ButtonsActions`

2012-may version:
```cpp
      v7 = (int *)sub_351DBF00(*((_DWORD *)this + 0x980), *((_DWORD *)this + 0x982), (int)this + 0x26B0);
      v8 = v7;
      if ( v7 && v7[1] < 47 )
      {
        if ( CEntity::IsLocalEntity(this) )
          sub_350E3260(v8, (int)this);
      }
```

2015-dic version:
```cpp
      v10 = sub_3530DAA0(*((_DWORD *)this + 0x9AE), *((_DWORD *)this + 0x9B0), (int)this + 0x2778);
      v11 = v10;
      if ( v10 )
      {
        if ( *(int *)(v10 + 4) < 160 && CEntity::IsLocalEntity(this) && *((_BYTE *)CPlayer::GetFieldInfo() + 313) != 1 )
        {
          v12 = *(void (__thiscall **)(CPlayer *, int, CPlayer *, int))(*(_DWORD *)this + 484);
          if ( *(_DWORD *)(v11 + 4) == 14 )
            v12(this, v11, this, 3);
          else
            v12(this, v11, this, 1);
        }
      }
```

The third argument of `sub_351DBF00` (2012-may version), and `sub_3530DAA0` (2015-dic version) is a buffer, and also is the value returned. That buffer is `struct CellInfo*` or `cplayer->CellInfo`. Let's see it.

```cpp
#ifdef 2012_MAY
struct CellInfoBySlot{
  DWORD   n_slot; // 0 to 3
  enum CellType cell_type;
  DWORD   unknow1;
  DWORD   unknow2; // flags?
  DWORD   unknow3;
  float   cell_points_cost;
  BYTE    cell_level;
  BYTE    unknow4;
  BYTE    unknow5;
  BYTE    unknow6;
  DWORD   padding; // ?
};
#endif

#ifdef 2015_DIC
struct CellInfoBySlot{
  DWORD   n_slot;
  enum CellType cell_type;
  enum    state;    // Encrypted: 0=Not enough points; 1=available; 2=summoned
  DWORD   unknow1;  //
  float   cell_points_cost;
  BYTE    cell_level;
  BYTE    unknow2;
  BYTE    unknow3;
  BYTE    unknow4;
  DWORD   unknow5;
};
#endif

struct CellInfo
{
  DWORD n_slot_available; // 0 to 3
  struct CellInfoBySlot cell_info_by_slot[3];
};
```

Then, We need to do following to modify the cell creatures: 

```cpp
struct CellInfo* pCellInfo = cplayer->CellInfo;
pCellInfo->cell_info_by_slot[0].cell_type = RedTaurus;
pCellInfo->cell_info_by_slot[0].cell_level = 99;
pCellInfo->cell_info_by_slot[0].cell_points_cost = 0;
```

<div align="center"><iframe width="560" height="315" src="https://www.youtube.com/embed/2AoSPE8bWSc" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen="">
</iframe><br>
<em>Editing cell creatures in-game (2012-may version)</em>
</div>
<br>
Now, in 2015-dic version we have a field called `state`, if we write always `pCellInfo->cell_info_by_slot[0].state = available` the first slot will be avaible to be summoned 'always' :D. Anyway, there is a check to bypass, let's review again the two functions mentioned before, `sub_35158F20(a2, a3, i);` (2015-dic version), and `void __cdecl sub_350E3260(int *a1, int a2)` (2012-may version) both of which have first argument `struct CellInfo*`.

2012-may version:
```cpp
void __cdecl sub_350E3260(int *a1, int a2)
{
  // [...]
  v20 = dword_353927B8;
  v2 = (*(int (__thiscall **)(_DWORD, int))(**(_DWORD **)_pRakionWorldNet + 8))(*(_DWORD *)_pRakionWorldNet, 1);
  if ( FieldInfo::IsRoundState(v2, v10[4]) )
  {
    if ( *(_BYTE *)(*(unsigned __int8 *)(*(_DWORD *)(*(_DWORD *)_pNetwork + 36) + 0x2946)
                  + *(_DWORD *)(*(_DWORD *)_pNetwork + 36)
                  + 0x2947) < 9u )
    {
      CPlacement3D::CPlacement3D(v14);
      v3 = (int *)sub_350E2EF0((int)v18, a2);
  // [...]
```

2015-dic version:
```cpp
void __cdecl sub_35158F20(int *a1, int a2, int a3)
{
  // [...]

  GlobalFieldInfo = GetGlobalFieldInfo();
  if ( FieldInfo::IsRoundState(GlobalFieldInfo, 1) )
  {
    if ( *((_BYTE *)GetGlobalFieldInfo() + 313) != 1
      && *(_BYTE *)(*(unsigned __int8 *)(*((_DWORD *)_pNetwork + 9) + 0x294C) + *((_DWORD *)_pNetwork + 9) + 0x294D) < 9u )
    {
      CPlacement3D::CPlacement3D((CPlacement3D *)v21);
  // [...]
```

What does those 'if statements' do? Basically checks that summoned creatures are not greater than 9. ¿Why 9?, because the cell creatures *white* spawn three creatures by slot. Then, we need to write constatly 0 in that address to bypass the check, as well as force to change the slot state to available, so we will be able to perform infinite creatures summons. Only is possible to summon one time per slot while the creature is still alive in-game, but in the following video you will see that I can summon many creatures from first slot. 

<div align="center"><iframe width="560" height="315" src="https://www.youtube.com/embed/2AoSPE8bWSc" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen="">
</iframe><br>
<em>Unlimited summons (2015-dic version)</em>
</div>
<br>
The `state` field is 'encrypted', I mean, that value changes constatly and it have a special way to write or read it. In a next blogpost I'll show you how we can do that, to make others cheats or you can see my talk at Ekoparty 2022 called [*The game (life) and how to hack it*][1] in spanish :D.


> Written by [**Nox**][5]

[1]:https://www.youtube.com/watch?v=LwOFWHnjSgA&t=2s
[5]:https://twitter.com/MrNox_
