# wkWall2Wall

wkWall2Wall is a WormKit module for Worms Armageddon Wall-X-Wall games.

[![wkWall2Wall presentation video](https://img.youtube.com/vi/un0RXMr11S8/hqdefault.jpg)](https://youtu.be/un0RXMr11S8)

When a match uses a map with prepared wall metadata, each turn becomes a small checklist:

- touch every configured wall
- collect at least one crate
- attack from the ninja rope when using a rope-droppable weapon

Touched walls are highlighted in-game. At the start of the next turn, the walls reset.

The project is open source so the W:A community can test it, fork it, improve it, and adapt it to more maps, renderers, schemes, and hosting setups.

## Current Release

The current build is a first public release candidate.

Download: [`release.zip`](release/release.zip)

Implemented gameplay:

- loads wall metadata from `.w2w.ini` files
- keeps untouched walls visually unchanged
- highlights touched walls
- resets touched walls from W:A turn-end messages
- detects wall contacts through W:A collision hooks
- supports rope collisions, walking contacts, jump contacts, and low-speed rope drop contacts
- blocks destructive attacks until all configured walls are touched
- blocks destructive attacks until at least one crate has been collected
- blocks rope-droppable attacks from foot; those attacks must be launched from rope
- plays custom sounds for wall touches, all-walls-touched, and blocked attack warnings
- stays passive on maps without matching wall metadata
- supports offline testing
- supports online host-to-client wall metadata sync when all players run a compatible wkWall2Wall

Renderer status:

- Direct3D 9: primary supported renderer
- DirectDraw: supported
- Direct3D 7: supported
- OpenGL: supported with a simpler opaque highlight fallback

## Installation

The easiest install path is the `release` folder.

Copy these items into your Worms Armageddon folder:

```text
release\wkWall2Wall.dll
release\wkWall2Wall.ini
release\User
```

After copying, the game folder should contain:

```text
Worms Armageddon\wkWall2Wall.dll
Worms Armageddon\wkWall2Wall.ini
Worms Armageddon\User\Walls
Worms Armageddon\User\Speech
```

Enable `Load WormKit modules` in W:A Advanced Settings, then restart W:A.

If something does not work, check:

```text
Worms Armageddon\wkWall2Wall.log
```

## Files And Folders

Wall metadata goes here:

```text
Worms Armageddon\User\Walls
```

Custom wkWall2Wall sounds go here:

```text
Worms Armageddon\User\Speech
```

Maps stay in the normal W:A map folder:

```text
Worms Armageddon\User\SavedLevels
```

The default `wkWall2Wall.ini` is intentionally small:

```ini
[General]
EnableModule=1
EnableOfflineMode=1
EnableOnlineSync=1
RequireAllPlayersOnline=1

[Walls]
MetadataDirectory=User\Walls

[Sounds]
Enabled=1
Volume=100
```

You can replace the default `.wav` files in `User\Speech`.

Blocked-attack warning sounds are local-only. `warning_walls.wav`, `warning_crate.wav`, and `warning_afr.wav` are played only for the active player on their own machine; other online players do not hear those warning sounds.

The default sound names are:

- `wall_touch_1.wav`
- `wall_touch_2.wav`
- `wall_touch_3.wav`
- `wall_touch_4.wav`
- `wall_touch_5.wav`
- `wall_touch_x.wav`
- `all_walls_touched.wav`
- `warning_walls.wav`
- `warning_crate.wav`
- `warning_afr.wav`

## Online Play

The online model is host-driven:

1. The host loads a map that has matching wall metadata.
2. wkWall2Wall checks that connected players have a compatible wkWall2Wall.
3. The host sends wall metadata to compatible clients.
4. Each player uses the host-provided wall rectangles.

If a connected player does not have a compatible wkWall2Wall, the module should stay passive and the match should behave normally.

Expected lobby messages include:

```text
wkWall2Wall: wall metadata loaded; checking wkWall2Wall clients.
wkWall2Wall: PlayerName has wkWall2Wall
wkWall2Wall: all connected players have a compatible wkWall2Wall.
wkWall2Wall: walls metadata received, ready to play!
```

## Known Issues And Workarounds

These are known release-candidate issues.

If the chat is already open at the beginning of a game, close it once before playing. This avoids a possible temporary overlay offset. After closing chat, wall highlights should be aligned correctly.

If W:A starts directly on a cached map, wkWall2Wall may not detect that map's metadata immediately. Workaround: load any random map once, then load the intended map with matching `.w2w.ini` metadata before starting the match.

`.BIT` map loading is not supported by the wall editor yet.

OpenGL uses a simpler highlight fallback than Direct3D 9.

## Creating Wall Metadata

Wall zones are stored in `.w2w.ini` files. The map image is not modified.

Use the wall editor:

```text
tools\wall-editor\index.html
```

Basic workflow:

1. Open the editor in a browser.
2. Choose a map image from `Worms Armageddon\User\SavedLevels`.
3. Draw rectangles around the Wall-X-Wall target walls.
4. Adjust the rectangles until they match the walls.
5. Export the `.w2w.ini` file.
6. Put the exported file in `Worms Armageddon\User\Walls`.

The editor is static HTML/CSS/JavaScript. No server is required.

## Building

Worms Armageddon is a 32-bit process, so the module must be built as a 32-bit DLL.

Build command:

```powershell
powershell -ExecutionPolicy Bypass -File tools\build.ps1 -RunTests
```

Output:

```text
build\llvm-mingw\wkWall2Wall.dll
```

## Repository Policy

Every DLL copied to the W:A folder and tested in-game should have:

- a commit
- the DLL SHA256 hash
- renderer and resolution notes
- scheme notes, especially manual or automatic worm placement
- a short result in `TEST_LOG.md`

This rule exists so regressions can be bisected instead of guessed.

## Contributing

Contributions are welcome.

Useful ways to help:

- test online host/client behavior
- test different W:A renderers and resolutions
- test manual and automatic worm placement schemes
- improve the wall editor
- add metadata for popular Wall-X-Wall maps
- improve documentation for players
- review hook safety and renderer compatibility

Please keep changes small and focused. In-game behavior should be documented in `TEST_LOG.md` when a DLL is built and tested.

## Safety

wkWall2Wall should not modify terrain physics or the map image.

The module should stay passive online unless every player in the match is running a compatible version.

## License

This project is released under the MIT License. See `LICENSE`.
