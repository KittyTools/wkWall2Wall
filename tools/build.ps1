param(
    [switch]$RunTests
)

$ErrorActionPreference = "Stop"

$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$toolchainRoot = Join-Path $projectRoot "tools\toolchains\llvm-mingw-20260602-msvcrt-i686"
$compiler = Join-Path $toolchainRoot "bin\i686-w64-mingw32-clang++.exe"
$readobj = Join-Path $toolchainRoot "bin\llvm-readobj.exe"
$buildDir = Join-Path $projectRoot "build\llvm-mingw"
$dllPath = Join-Path $buildDir "wkWall2Wall.dll"

if (-not (Test-Path -LiteralPath $compiler)) {
    throw "Missing compiler: $compiler"
}

New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

$sources = @(
    "src\Config.cpp",
    "src\WallGameMessage.cpp",
    "src\WaHooks.cpp",
    "src\WaMemory.cpp",
    "src\WaTaskMessageCodec.cpp",
    "src\Logger.cpp",
    "src\Version.cpp",
    "src\WallMetadata.cpp",
    "src\WallProtocol.cpp",
    "src\WallSession.cpp",
    "src\WallSync.cpp",
    "src\WallTouch.cpp",
    "src\WallTransport.cpp",
    "src\dllmain.cpp"
) | ForEach-Object { Join-Path $projectRoot $_ }

$arguments = @(
    "-std=c++20",
    "-O2",
    "-Wall",
    "-Wextra",
    "-DWIN32_LEAN_AND_MEAN",
    "-DNOMINMAX",
    "-shared"
) + $sources + @(
    "-o",
    $dllPath,
    "-lversion",
    "-static",
    "-Wl,--exclude-all-symbols"
)

& $compiler @arguments
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$headers = (& $readobj --file-headers $dllPath) -join "`n"
if ($headers -notmatch "Format: COFF-i386" -or $headers -notmatch "AddressSize: 32bit") {
    throw "Build output is not a 32-bit i386 PE DLL."
}

Write-Host "Built $dllPath"

if ($RunTests) {
    $testPath = Join-Path $buildDir "protocol_smoke_test.exe"
    $testSources = @(
        (Join-Path $projectRoot "tools\protocol_smoke_test.cpp"),
        (Join-Path $projectRoot "src\WallGameMessage.cpp"),
        (Join-Path $projectRoot "src\WaMemory.cpp"),
        (Join-Path $projectRoot "src\WaTaskMessageCodec.cpp"),
        (Join-Path $projectRoot "src\WallProtocol.cpp"),
        (Join-Path $projectRoot "src\WallSession.cpp"),
        (Join-Path $projectRoot "src\WallSync.cpp"),
        (Join-Path $projectRoot "src\WallTouch.cpp"),
        (Join-Path $projectRoot "src\WallTransport.cpp")
    )

    $testArguments = @(
        "-std=c++20",
        "-O2",
        "-Wall",
        "-Wextra",
        "-DWIN32_LEAN_AND_MEAN",
        "-DNOMINMAX",
        "-I",
        (Join-Path $projectRoot "src")
    ) + $testSources + @(
        "-o",
        $testPath,
        "-static"
    )

    & $compiler @testArguments
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    & $testPath
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}
