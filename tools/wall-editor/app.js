const elements = {
  mapInput: document.getElementById("mapInput"),
  iniInput: document.getElementById("iniInput"),
  mapInfo: document.getElementById("mapInfo"),
  canvas: document.getElementById("mapCanvas"),
  canvasWrap: document.getElementById("canvasWrap"),
  emptyState: document.getElementById("emptyState"),
  cursorInfo: document.getElementById("cursorInfo"),
  zoomInfo: document.getElementById("zoomInfo"),
  wallCount: document.getElementById("wallCount"),
  wallList: document.getElementById("wallList"),
  exportButton: document.getElementById("exportButton"),
  status: document.getElementById("status"),
  zoomOutButton: document.getElementById("zoomOutButton"),
  zoomInButton: document.getElementById("zoomInButton"),
  fitButton: document.getElementById("fitButton"),
  oneToOneButton: document.getElementById("oneToOneButton"),
  drawModeButton: document.getElementById("drawModeButton"),
  panModeButton: document.getElementById("panModeButton"),
  undoButton: document.getElementById("undoButton"),
  redoButton: document.getElementById("redoButton"),
  deleteButton: document.getElementById("deleteButton"),
  clearButton: document.getElementById("clearButton"),
  modeInfo: document.getElementById("modeInfo"),
  emptyInspector: document.getElementById("emptyInspector"),
  wallInspector: document.getElementById("wallInspector"),
  wallName: document.getElementById("wallName"),
  wallX: document.getElementById("wallX"),
  wallY: document.getElementById("wallY"),
  wallW: document.getElementById("wallW"),
  wallH: document.getElementById("wallH"),
  wallColor: document.getElementById("wallColor"),
};

const context = elements.canvas.getContext("2d");

const state = {
  image: null,
  imageUrl: "",
  mapFileName: "",
  mapName: "",
  mapSha256: "",
  mapWidth: 0,
  mapHeight: 0,
  zoom: 1,
  mode: "draw",
  spacePanning: false,
  walls: [],
  selectedId: null,
  drag: null,
  nextWallId: 1,
  history: [],
  redoStack: [],
  pendingInspectorSnapshot: null,
};

function setStatus(message) {
  elements.status.textContent = message;
}

function cloneWalls(walls) {
  return walls.map((wall) => ({ ...wall }));
}

function captureSnapshot() {
  return {
    walls: cloneWalls(state.walls),
    selectedId: state.selectedId,
    nextWallId: state.nextWallId,
  };
}

function snapshotsEqual(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function restoreSnapshot(snapshot) {
  state.walls = cloneWalls(snapshot.walls);
  state.selectedId = state.walls.some((wall) => wall.id === snapshot.selectedId) ? snapshot.selectedId : null;
  state.nextWallId = snapshot.nextWallId;
  state.drag = null;
  state.pendingInspectorSnapshot = null;
  refreshInspector();
  refreshWallList();
  draw();
  updateActionButtons();
}

function pushHistory(snapshot = captureSnapshot()) {
  const current = captureSnapshot();
  if (snapshotsEqual(snapshot, current)) {
    return;
  }

  state.history.push(snapshot);
  if (state.history.length > 100) {
    state.history.shift();
  }
  state.redoStack = [];
  updateActionButtons();
}

function resetHistory() {
  state.history = [];
  state.redoStack = [];
  state.pendingInspectorSnapshot = null;
  updateActionButtons();
}

function undoChange() {
  if (!state.history.length) {
    setStatus("Nothing to undo.");
    return;
  }

  const previous = state.history.pop();
  state.redoStack.push(captureSnapshot());
  restoreSnapshot(previous);
  setStatus("Last change undone.");
}

function redoChange() {
  if (!state.redoStack.length) {
    setStatus("Nothing to redo.");
    return;
  }

  const next = state.redoStack.pop();
  state.history.push(captureSnapshot());
  restoreSnapshot(next);
  setStatus("Last undone change restored.");
}

function updateActionButtons() {
  elements.undoButton.disabled = state.history.length === 0;
  elements.redoButton.disabled = state.redoStack.length === 0;
  elements.deleteButton.disabled = !state.selectedId;
}

function setZoom(zoom) {
  state.zoom = Math.max(0.1, Math.min(8, zoom));
  resizeCanvas();
  draw();
  updateCanvasCursor();
}

function zoomAtClientPoint(zoom, clientX, clientY) {
  if (!state.image) {
    return;
  }

  const oldZoom = state.zoom;
  const nextZoom = Math.max(0.1, Math.min(8, zoom));
  if (nextZoom === oldZoom) {
    return;
  }

  const canvasRect = elements.canvas.getBoundingClientRect();
  const wrapRect = elements.canvasWrap.getBoundingClientRect();
  const imageX = (clientX - canvasRect.left) / oldZoom;
  const imageY = (clientY - canvasRect.top) / oldZoom;
  const viewportX = clientX - wrapRect.left;
  const viewportY = clientY - wrapRect.top;

  state.zoom = nextZoom;
  resizeCanvas();
  draw();

  elements.canvasWrap.scrollLeft = imageX * nextZoom - viewportX + elements.canvas.offsetLeft;
  elements.canvasWrap.scrollTop = imageY * nextZoom - viewportY + elements.canvas.offsetTop;
  updateCanvasCursor();
}

function setMode(mode) {
  state.mode = mode === "pan" ? "pan" : "draw";
  updateModeUi();
  updateCanvasCursor();
}

function isPanActive() {
  return state.mode === "pan" || state.spacePanning;
}

function effectiveMode() {
  return isPanActive() ? "pan" : "draw";
}

function updateModeUi() {
  const mode = effectiveMode();
  const temporaryPan = state.spacePanning && state.mode !== "pan";
  elements.drawModeButton.classList.toggle("active", mode === "draw");
  elements.panModeButton.classList.toggle("active", mode === "pan");
  elements.panModeButton.classList.toggle("temporary", temporaryPan);
  elements.drawModeButton.setAttribute("aria-pressed", String(mode === "draw"));
  elements.panModeButton.setAttribute("aria-pressed", String(mode === "pan"));

  if (temporaryPan) {
    elements.modeInfo.textContent = "mode: Pan (Space)";
  } else if (state.mode === "pan") {
    elements.modeInfo.textContent = "mode: Pan";
  } else {
    elements.modeInfo.textContent = "mode: Draw - hold Space for Pan";
  }
}

function shouldStartPan(event) {
  return event.button === 1 || isPanActive();
}

function updateCanvasCursor(point = null) {
  if (!state.image) {
    elements.canvas.style.cursor = "default";
    return;
  }

  if (state.drag?.mode === "pan") {
    elements.canvas.style.cursor = "grabbing";
    return;
  }

  if (isPanActive()) {
    elements.canvas.style.cursor = "grab";
    return;
  }

  if (point) {
    const hit = hitTest(point);
    elements.canvas.style.cursor = hit ? cursorForHandle(hit.handle) : "crosshair";
    return;
  }

  elements.canvas.style.cursor = "crosshair";
}

function fitToView() {
  if (!state.image) {
    return;
  }
  const availableWidth = Math.max(240, elements.canvasWrap.clientWidth - 48);
  const availableHeight = Math.max(180, elements.canvasWrap.clientHeight - 48);
  setZoom(Math.min(availableWidth / state.mapWidth, availableHeight / state.mapHeight, 1));
}

function resizeCanvas() {
  if (!state.image) {
    elements.canvas.width = 1280;
    elements.canvas.height = 720;
    elements.zoomInfo.textContent = "zoom: 100%";
    return;
  }
  elements.canvas.width = Math.max(1, Math.round(state.mapWidth * state.zoom));
  elements.canvas.height = Math.max(1, Math.round(state.mapHeight * state.zoom));
  elements.zoomInfo.textContent = `zoom: ${Math.round(state.zoom * 100)}%`;
}

function draw() {
  context.clearRect(0, 0, elements.canvas.width, elements.canvas.height);
  if (!state.image) {
    return;
  }

  context.imageSmoothingEnabled = false;
  context.drawImage(state.image, 0, 0, elements.canvas.width, elements.canvas.height);

  for (const wall of state.walls) {
    drawWall(wall, wall.id === state.selectedId);
  }

  if (state.drag?.mode === "create" && state.drag.draft) {
    drawWall(state.drag.draft, true, true);
  }
}

function drawWall(wall, selected, draft = false) {
  const x = Math.round(wall.x * state.zoom);
  const y = Math.round(wall.y * state.zoom);
  const width = Math.round(wall.w * state.zoom);
  const height = Math.round(wall.h * state.zoom);

  context.save();
  context.lineWidth = selected ? 3 : 2;
  context.strokeStyle = draft ? "#ffffff" : wall.color;
  context.fillStyle = hexToRgba(wall.color, selected ? 0.18 : 0.08);
  context.fillRect(x, y, width, height);
  context.strokeRect(x, y, width, height);
  context.font = "bold 14px Segoe UI, sans-serif";
  context.textBaseline = "top";
  context.fillStyle = "rgba(0, 0, 0, 0.72)";
  context.fillRect(x + 4, y + 4, 62, 22);
  context.fillStyle = draft ? "#ffffff" : wall.color;
  context.fillText(wall.name || "Wall", x + 9, y + 7);

  if (selected && !draft) {
    for (const handle of getHandlePoints(wall)) {
      const size = 8;
      context.fillStyle = "#ffffff";
      context.strokeStyle = "#000000";
      context.lineWidth = 1;
      context.fillRect(handle.x * state.zoom - size / 2, handle.y * state.zoom - size / 2, size, size);
      context.strokeRect(handle.x * state.zoom - size / 2, handle.y * state.zoom - size / 2, size, size);
    }
  }
  context.restore();
}

function hexToRgba(hex, alpha) {
  const value = hex.replace("#", "");
  const r = parseInt(value.slice(0, 2), 16);
  const g = parseInt(value.slice(2, 4), 16);
  const b = parseInt(value.slice(4, 6), 16);
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

function getCanvasPoint(event) {
  const rect = elements.canvas.getBoundingClientRect();
  const x = (event.clientX - rect.left) / state.zoom;
  const y = (event.clientY - rect.top) / state.zoom;
  return {
    x: clamp(Math.round(x), 0, Math.max(0, state.mapWidth - 1)),
    y: clamp(Math.round(y), 0, Math.max(0, state.mapHeight - 1)),
  };
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function normalizeRect(start, end) {
  const x1 = clamp(Math.min(start.x, end.x), 0, Math.max(0, state.mapWidth - 1));
  const y1 = clamp(Math.min(start.y, end.y), 0, Math.max(0, state.mapHeight - 1));
  const x2 = clamp(Math.max(start.x, end.x), 0, Math.max(0, state.mapWidth - 1));
  const y2 = clamp(Math.max(start.y, end.y), 0, Math.max(0, state.mapHeight - 1));
  return {
    x: x1,
    y: y1,
    w: Math.max(1, x2 - x1 + 1),
    h: Math.max(1, y2 - y1 + 1),
  };
}

function createWall(rect) {
  const before = captureSnapshot();
  const wall = {
    id: state.nextWallId++,
    name: `Wall${state.nextWallId - 1}`,
    x: rect.x,
    y: rect.y,
    w: rect.w,
    h: rect.h,
    color: "#00ff00",
  };
  state.walls.push(wall);
  selectWall(wall.id);
  refreshWallList();
  draw();
  pushHistory(before);
}

function selectWall(id) {
  state.selectedId = id;
  refreshInspector();
  refreshWallList();
  draw();
  updateActionButtons();
}

function getSelectedWall() {
  return state.walls.find((wall) => wall.id === state.selectedId) || null;
}

function hitTest(point) {
  const selected = getSelectedWall();
  if (selected) {
    const handle = hitHandle(point, selected);
    if (handle) {
      return { wall: selected, mode: "resize", handle };
    }
  }

  for (let index = state.walls.length - 1; index >= 0; index--) {
    const wall = state.walls[index];
    if (point.x >= wall.x && point.x <= wall.x + wall.w && point.y >= wall.y && point.y <= wall.y + wall.h) {
      return { wall, mode: "move", handle: "move" };
    }
  }

  return null;
}

function getHandlePoints(wall) {
  const x1 = wall.x;
  const y1 = wall.y;
  const x2 = wall.x + wall.w;
  const y2 = wall.y + wall.h;
  const cx = wall.x + wall.w / 2;
  const cy = wall.y + wall.h / 2;
  return [
    { name: "nw", x: x1, y: y1 },
    { name: "n", x: cx, y: y1 },
    { name: "ne", x: x2, y: y1 },
    { name: "e", x: x2, y: cy },
    { name: "se", x: x2, y: y2 },
    { name: "s", x: cx, y: y2 },
    { name: "sw", x: x1, y: y2 },
    { name: "w", x: x1, y: cy },
  ];
}

function hitHandle(point, wall) {
  const tolerance = Math.max(5, 10 / state.zoom);
  for (const handle of getHandlePoints(wall)) {
    if (Math.abs(point.x - handle.x) <= tolerance && Math.abs(point.y - handle.y) <= tolerance) {
      return handle.name;
    }
  }
  return null;
}

function resizeRect(original, start, current, handle) {
  let left = original.x;
  let top = original.y;
  let right = original.x + original.w - 1;
  let bottom = original.y + original.h - 1;
  const dx = current.x - start.x;
  const dy = current.y - start.y;

  if (handle.includes("w")) {
    left += dx;
  }
  if (handle.includes("e")) {
    right += dx;
  }
  if (handle.includes("n")) {
    top += dy;
  }
  if (handle.includes("s")) {
    bottom += dy;
  }

  left = clamp(left, 0, Math.max(0, state.mapWidth - 1));
  right = clamp(right, 0, Math.max(0, state.mapWidth - 1));
  top = clamp(top, 0, Math.max(0, state.mapHeight - 1));
  bottom = clamp(bottom, 0, Math.max(0, state.mapHeight - 1));

  const x1 = Math.min(left, right);
  const x2 = Math.max(left, right);
  const y1 = Math.min(top, bottom);
  const y2 = Math.max(top, bottom);

  return {
    x: x1,
    y: y1,
    w: Math.max(1, x2 - x1 + 1),
    h: Math.max(1, y2 - y1 + 1),
  };
}

function moveRect(original, start, current) {
  const x = clamp(original.x + current.x - start.x, 0, Math.max(0, state.mapWidth - original.w));
  const y = clamp(original.y + current.y - start.y, 0, Math.max(0, state.mapHeight - original.h));
  return { x, y, w: original.w, h: original.h };
}

function applyRect(wall, rect) {
  wall.x = Math.round(rect.x);
  wall.y = Math.round(rect.y);
  wall.w = Math.round(rect.w);
  wall.h = Math.round(rect.h);
}

function rectChanged(left, right) {
  return left.x !== right.x || left.y !== right.y || left.w !== right.w || left.h !== right.h;
}

async function loadMap(file) {
  if (!file) {
    return;
  }

  if (state.imageUrl) {
    URL.revokeObjectURL(state.imageUrl);
    state.imageUrl = "";
  }

  const bytes = new Uint8Array(await file.arrayBuffer());
  const loaded = await loadImageElement(file);
  const image = loaded.image;
  state.imageUrl = loaded.url;

  state.image = image;
  state.mapFileName = file.name;
  state.mapName = stripExtension(file.name);
  state.mapWidth = image.naturalWidth;
  state.mapHeight = image.naturalHeight;
  state.mapSha256 = sha256Bytes(bytes);
  state.walls = [];
  state.selectedId = null;
  state.nextWallId = 1;
  resetHistory();

  elements.emptyState.classList.add("hidden");
  elements.mapInfo.textContent = `${state.mapFileName} - ${state.mapWidth}x${state.mapHeight} - sha256 ${state.mapSha256.slice(0, 12)}...`;
  fitToView();
  refreshInspector();
  refreshWallList();
  updateCanvasCursor();
  setStatus("Map loaded. Drag rectangles around each wall.");
}

function stripExtension(fileName) {
  return fileName.replace(/\.[^/.]+$/, "");
}

async function loadImageElement(file) {
  const image = new Image();
  const url = URL.createObjectURL(file);
  image.src = url;
  try {
    await image.decode();
  } catch (error) {
    URL.revokeObjectURL(url);
    throw error;
  }
  return { image, url };
}

async function importIni(file) {
  if (!file) {
    return;
  }
  const text = await file.text();
  const parsed = parseIni(text);
  const importedWalls = [];
  const count = Number(parsed.Map?.WallCount || 0);
  const before = captureSnapshot();
  let nextId = 1;

  for (let index = 1; index <= count; index++) {
    const section = parsed[`Wall.${index}`];
    if (!section) {
      continue;
    }
    importedWalls.push({
      id: nextId++,
      name: section.Name || `Wall${index}`,
      x: Number(section.X || 0),
      y: Number(section.Y || 0),
      w: Math.max(1, Number(section.W || 1)),
      h: Math.max(1, Number(section.H || 1)),
      color: normalizeColor(section.Color || "00FF00"),
    });
  }

  state.walls = importedWalls;
  state.nextWallId = nextId;
  state.selectedId = importedWalls[0]?.id || null;
  refreshInspector();
  refreshWallList();
  draw();
  pushHistory(before);
  setStatus(`Imported ${importedWalls.length} wall(s) from ${file.name}.`);
}

function parseIni(text) {
  const result = {};
  let current = null;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith(";") || line.startsWith("#")) {
      continue;
    }
    const section = line.match(/^\[([^\]]+)]$/);
    if (section) {
      current = section[1];
      result[current] = result[current] || {};
      continue;
    }
    const equals = line.indexOf("=");
    if (equals > -1 && current) {
      const key = line.slice(0, equals).trim();
      const value = line.slice(equals + 1).trim();
      result[current][key] = value;
    }
  }
  return result;
}

function normalizeColor(value) {
  const hex = value.replace("#", "").trim();
  if (/^[0-9a-fA-F]{6}$/.test(hex)) {
    return `#${hex.toLowerCase()}`;
  }
  return "#00ff00";
}

function refreshWallList() {
  elements.wallCount.textContent = String(state.walls.length);
  elements.wallList.innerHTML = "";
  for (const wall of state.walls) {
    const item = document.createElement("li");
    item.className = wall.id === state.selectedId ? "active" : "";
    item.innerHTML = `<div><strong>${escapeHtml(wall.name)}</strong><span>x:${wall.x} y:${wall.y} w:${wall.w} h:${wall.h}</span></div><span class="color-chip" style="background:${wall.color}"></span>`;
    item.addEventListener("click", () => selectWall(wall.id));
    elements.wallList.appendChild(item);
  }
}

function refreshInspector() {
  const wall = getSelectedWall();
  elements.emptyInspector.classList.toggle("hidden", Boolean(wall));
  elements.wallInspector.classList.toggle("hidden", !wall);
  if (!wall) {
    return;
  }
  elements.wallName.value = wall.name;
  elements.wallX.value = String(wall.x);
  elements.wallY.value = String(wall.y);
  elements.wallW.value = String(wall.w);
  elements.wallH.value = String(wall.h);
  elements.wallColor.value = wall.color;
}

function beginInspectorEdit() {
  if (!state.pendingInspectorSnapshot) {
    state.pendingInspectorSnapshot = captureSnapshot();
  }
}

function commitInspectorEdit() {
  if (!state.pendingInspectorSnapshot) {
    return;
  }

  pushHistory(state.pendingInspectorSnapshot);
  state.pendingInspectorSnapshot = null;
}

function updateSelectedFromInspector() {
  const wall = getSelectedWall();
  if (!wall) {
    return;
  }
  wall.name = elements.wallName.value.trim() || wall.name;
  wall.x = clamp(Number(elements.wallX.value || 0), 0, Math.max(0, state.mapWidth - 1));
  wall.y = clamp(Number(elements.wallY.value || 0), 0, Math.max(0, state.mapHeight - 1));
  wall.w = clamp(Number(elements.wallW.value || 1), 1, Math.max(1, state.mapWidth - wall.x));
  wall.h = clamp(Number(elements.wallH.value || 1), 1, Math.max(1, state.mapHeight - wall.y));
  wall.color = elements.wallColor.value;
  refreshWallList();
  draw();
  updateActionButtons();
}

function exportIni() {
  if (!state.image) {
    setStatus("Load a map before exporting.");
    return;
  }

  const lines = [];
  lines.push("[Map]");
  lines.push(`Name = ${state.mapName}`);
  lines.push(`File = ${state.mapFileName}`);
  lines.push(`Sha256 = ${state.mapSha256}`);
  lines.push(`Width = ${state.mapWidth}`);
  lines.push(`Height = ${state.mapHeight}`);
  lines.push(`WallCount = ${state.walls.length}`);
  lines.push("");

  state.walls.forEach((wall, index) => {
    lines.push(`[Wall.${index + 1}]`);
    lines.push(`Name = ${wall.name || `Wall${index + 1}`}`);
    lines.push("Type = Rect");
    lines.push(`X = ${Math.round(wall.x)}`);
    lines.push(`Y = ${Math.round(wall.y)}`);
    lines.push(`W = ${Math.round(wall.w)}`);
    lines.push(`H = ${Math.round(wall.h)}`);
    lines.push(`Color = ${wall.color.replace("#", "").toUpperCase()}`);
    lines.push("");
  });

  const blob = new Blob([lines.join("\n")], { type: "text/plain;charset=utf-8" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `${state.mapName}.w2w.ini`;
  link.click();
  URL.revokeObjectURL(link.href);
  setStatus(`Exported ${state.walls.length} wall(s).`);
}

function deleteSelectedWall() {
  if (!state.selectedId) {
    setStatus("No wall selected.");
    return;
  }

  const snapshot = captureSnapshot();
  const beforeCount = state.walls.length;
  state.walls = state.walls.filter((wall) => wall.id !== state.selectedId);
  if (state.walls.length !== beforeCount) {
    state.selectedId = state.walls.at(-1)?.id || null;
    refreshInspector();
    refreshWallList();
    draw();
    pushHistory(snapshot);
    setStatus("Selected wall deleted.");
  }
}

function clearWalls() {
  if (!state.walls.length) {
    setStatus("No walls to clear.");
    return;
  }

  const before = captureSnapshot();
  state.walls = [];
  state.selectedId = null;
  refreshInspector();
  refreshWallList();
  draw();
  pushHistory(before);
  setStatus("All walls cleared.");
}

function escapeHtml(value) {
  return value.replace(/[&<>"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;" }[char]));
}

function cursorForHandle(handle) {
  const cursors = {
    n: "ns-resize",
    s: "ns-resize",
    e: "ew-resize",
    w: "ew-resize",
    nw: "nwse-resize",
    se: "nwse-resize",
    ne: "nesw-resize",
    sw: "nesw-resize",
    move: "move",
  };
  return cursors[handle] || "crosshair";
}

function sha256Bytes(bytes) {
  const words = [];
  const bitLength = bytes.length * 8;
  for (let index = 0; index < bytes.length; index++) {
    words[index >> 2] |= bytes[index] << (24 - (index % 4) * 8);
  }
  words[bitLength >> 5] |= 0x80 << (24 - bitLength % 32);
  words[((bitLength + 64 >> 9) << 4) + 15] = bitLength;

  const constants = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  let hash = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  const work = new Array(64);

  for (let offset = 0; offset < words.length; offset += 16) {
    for (let index = 0; index < 64; index++) {
      if (index < 16) {
        work[index] = words[offset + index] | 0;
      } else {
        const gamma0 = rightRotate(work[index - 15], 7) ^ rightRotate(work[index - 15], 18) ^ (work[index - 15] >>> 3);
        const gamma1 = rightRotate(work[index - 2], 17) ^ rightRotate(work[index - 2], 19) ^ (work[index - 2] >>> 10);
        work[index] = (work[index - 16] + gamma0 + work[index - 7] + gamma1) | 0;
      }
    }

    let [a, b, c, d, e, f, g, h] = hash;
    for (let index = 0; index < 64; index++) {
      const ch = (e & f) ^ (~e & g);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const sigma0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
      const sigma1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
      const t1 = (h + sigma1 + ch + constants[index] + work[index]) | 0;
      const t2 = (sigma0 + maj) | 0;
      h = g;
      g = f;
      f = e;
      e = (d + t1) | 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) | 0;
    }

    hash = hash.map((value, index) => (value + [a, b, c, d, e, f, g, h][index]) | 0);
  }

  return hash.map((value) => (value >>> 0).toString(16).padStart(8, "0")).join("");
}

function rightRotate(value, amount) {
  return (value >>> amount) | (value << (32 - amount));
}

async function handleMapInput(event) {
  try {
    await loadMap(event.target.files[0]);
  } catch (error) {
    setStatus(error instanceof Error ? error.message : "Map load failed.");
  }
}

elements.mapInput.addEventListener("change", handleMapInput);
elements.iniInput.addEventListener("change", (event) => importIni(event.target.files[0]));
elements.exportButton.addEventListener("click", exportIni);
elements.zoomOutButton.addEventListener("click", () => setZoom(state.zoom / 1.25));
elements.zoomInButton.addEventListener("click", () => setZoom(state.zoom * 1.25));
elements.fitButton.addEventListener("click", fitToView);
elements.oneToOneButton.addEventListener("click", () => setZoom(1));
elements.drawModeButton.addEventListener("click", () => setMode("draw"));
elements.panModeButton.addEventListener("click", () => setMode("pan"));
elements.canvas.addEventListener("wheel", (event) => {
  if (!state.image) {
    return;
  }
  event.preventDefault();
  const factor = event.deltaY < 0 ? 1.15 : 1 / 1.15;
  zoomAtClientPoint(state.zoom * factor, event.clientX, event.clientY);
}, { passive: false });
elements.undoButton.addEventListener("click", undoChange);
elements.redoButton.addEventListener("click", redoChange);
elements.deleteButton.addEventListener("click", deleteSelectedWall);
elements.clearButton.addEventListener("click", clearWalls);

for (const input of [elements.wallName, elements.wallX, elements.wallY, elements.wallW, elements.wallH, elements.wallColor]) {
  input.addEventListener("focus", beginInspectorEdit);
  input.addEventListener("input", updateSelectedFromInspector);
  input.addEventListener("change", commitInspectorEdit);
  input.addEventListener("blur", commitInspectorEdit);
}

elements.canvas.addEventListener("pointerdown", (event) => {
  if (!state.image) {
    return;
  }

  event.preventDefault();
  elements.canvas.setPointerCapture(event.pointerId);

  if (shouldStartPan(event)) {
    state.drag = {
      mode: "pan",
      startClientX: event.clientX,
      startClientY: event.clientY,
      scrollLeft: elements.canvasWrap.scrollLeft,
      scrollTop: elements.canvasWrap.scrollTop,
    };
    updateCanvasCursor();
    return;
  }

  if (event.button !== 0) {
    elements.canvas.releasePointerCapture(event.pointerId);
    return;
  }

  const point = getCanvasPoint(event);
  const hit = hitTest(point);

  if (hit) {
    selectWall(hit.wall.id);
    state.drag = {
      mode: hit.mode,
      handle: hit.handle,
      start: point,
      original: { x: hit.wall.x, y: hit.wall.y, w: hit.wall.w, h: hit.wall.h },
      historySnapshot: captureSnapshot(),
      wallId: hit.wall.id,
    };
    updateCanvasCursor(point);
  } else {
    state.drag = {
      mode: "create",
      start: point,
      draft: { id: 0, name: "New", x: point.x, y: point.y, w: 1, h: 1, color: "#ffffff" },
    };
    selectWall(null);
  }
});

elements.canvas.addEventListener("pointermove", (event) => {
  if (!state.image) {
    return;
  }
  const point = getCanvasPoint(event);
  elements.cursorInfo.textContent = `x: ${point.x}, y: ${point.y}`;

  if (state.drag?.mode === "pan") {
    elements.canvasWrap.scrollLeft = state.drag.scrollLeft + state.drag.startClientX - event.clientX;
    elements.canvasWrap.scrollTop = state.drag.scrollTop + state.drag.startClientY - event.clientY;
    return;
  }

  if (!state.drag) {
    updateCanvasCursor(point);
    return;
  }

  if (state.drag.mode === "create") {
    state.drag.draft = {
      id: 0,
      name: "New",
      color: "#ffffff",
      ...normalizeRect(state.drag.start, point),
    };
  } else {
    const wall = state.walls.find((item) => item.id === state.drag.wallId);
    if (wall) {
      const rect = state.drag.mode === "resize"
        ? resizeRect(state.drag.original, state.drag.start, point, state.drag.handle)
        : moveRect(state.drag.original, state.drag.start, point);
      applyRect(wall, rect);
      refreshInspector();
      refreshWallList();
    }
  }
  draw();
});

elements.canvas.addEventListener("pointerup", (event) => {
  if (!state.drag) {
    return;
  }

  if (state.drag.mode === "pan") {
    state.drag = null;
    elements.canvas.releasePointerCapture(event.pointerId);
    updateCanvasCursor();
    return;
  }

  if (state.drag.mode === "create" && state.drag.draft && state.drag.draft.w >= 3 && state.drag.draft.h >= 3) {
    createWall(state.drag.draft);
    setStatus("Wall rectangle added.");
  }

  if ((state.drag.mode === "move" || state.drag.mode === "resize") && state.drag.historySnapshot) {
    const wall = state.walls.find((item) => item.id === state.drag.wallId);
    if (wall && rectChanged(state.drag.original, wall)) {
      pushHistory(state.drag.historySnapshot);
      setStatus("Wall rectangle updated.");
    }
  }

  state.drag = null;
  elements.canvas.releasePointerCapture(event.pointerId);
  updateCanvasCursor();
  draw();
});

elements.canvas.addEventListener("pointercancel", (event) => {
  if (!state.drag) {
    return;
  }
  state.drag = null;
  elements.canvas.releasePointerCapture(event.pointerId);
  updateCanvasCursor();
  draw();
});

elements.canvas.addEventListener("pointerleave", () => {
  elements.cursorInfo.textContent = "x: -, y: -";
});

elements.canvas.addEventListener("contextmenu", (event) => {
  event.preventDefault();
});

document.addEventListener("keydown", (event) => {
  const activeTag = document.activeElement.tagName;
  const isEditingText = ["INPUT", "TEXTAREA", "SELECT"].includes(activeTag);

  if (event.code === "Space" && !isEditingText && !state.spacePanning) {
    event.preventDefault();
    state.spacePanning = true;
    updateModeUi();
    updateCanvasCursor();
    return;
  }

  if (event.key === "Delete" || event.key === "Backspace") {
    if (!isEditingText) {
      event.preventDefault();
      deleteSelectedWall();
    }
  }

  if (isEditingText || (!event.ctrlKey && !event.metaKey)) {
    return;
  }

  const key = event.key.toLowerCase();
  if (key === "z" && !event.shiftKey) {
    event.preventDefault();
    undoChange();
  }
  if ((key === "y" && !event.shiftKey) || (key === "z" && event.shiftKey)) {
    event.preventDefault();
    redoChange();
  }
});

document.addEventListener("keyup", (event) => {
  if (event.code === "Space") {
    state.spacePanning = false;
    updateModeUi();
    updateCanvasCursor();
  }
});

window.addEventListener("blur", () => {
  if (!state.spacePanning) {
    return;
  }
  state.spacePanning = false;
  updateModeUi();
  updateCanvasCursor();
});

setMode("draw");
resizeCanvas();
draw();
updateActionButtons();
