/* =====================================================================
   TSM79 v4 — WEBGPU ENGINE  (ES module)
   ---------------------------------------------------------------------
   Implements the shader.se-class pipeline described in the brief:
     · THREE.WebGPURenderer  (auto-falls-back to WebGL2)
     · TSL node post-processing:  pass → bloom → chromatic aberration
       + film grain, compiled to a single output node
     · cursor-velocity FLOWMAP driving directional chromatic aberration
     · 90-frame IDLE GUARD that suspends the loop when input stops
     · graceful canvas-2D fallback if WebGPU / TSL fail to load
   The whole thing is wrapped in try/catch so a failure never blanks the
   page — the DOM content + UI run independently in landing_v4.js.
   ===================================================================== */

const container = document.getElementById('hero-webgl');

/* shared pointer state (also read by the 2D fallback) */
const ptr = { x: 0.5, y: 0.5, px: 0.5, py: 0.5, vx: 0, vy: 0, vel: 0, moved: 0 };
addEventListener('pointermove', (e) => {
  const nx = e.clientX / innerWidth;
  const ny = e.clientY / innerHeight;
  ptr.vx = nx - ptr.x; ptr.vy = ny - ptr.y;
  ptr.x = nx; ptr.y = ny;
  ptr.vel = Math.min(1, Math.hypot(ptr.vx, ptr.vy) * 14);
  ptr.moved = performance.now();
}, { passive: true });

let engineMode = 'pending';

async function initWebGPU() {
  if (!container) throw new Error('no hero container');

  const THREE = await import('three');
  const TSL = await import('three/tsl');

  // --- Renderer (WebGPU first, WebGL2 fallback handled internally) ---
  const renderer = new THREE.WebGPURenderer({
    antialias: true, alpha: true, powerPreference: 'high-performance',
  });
  await renderer.init();
  renderer.setClearColor(0x050505, 0);
  renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
  container.appendChild(renderer.domElement);
  Object.assign(renderer.domElement.style, { width: '100%', height: '100%', display: 'block' });

  engineMode = renderer.backend && /gpu/i.test(renderer.backend.constructor.name) ? 'webgpu' : 'webgl2';

  const scene = new THREE.Scene();
  scene.fog = new THREE.FogExp2(0x050505, 0.034);
  const cam = new THREE.PerspectiveCamera(48, 1, 0.1, 200);
  cam.position.set(0, 0, 22);

  const setSize = () => {
    const r = container.getBoundingClientRect();
    renderer.setSize(r.width, r.height, false);
    cam.aspect = r.width / r.height;
    cam.updateProjectionMatrix();
  };
  setSize();
  addEventListener('resize', setSize);

  /* ---------- NODE GRAPH (bright → blooms) ---------- */
  const NODES = 70;
  const nodes = [];
  for (let i = 0; i < NODES; i++) {
    nodes.push({
      p: new THREE.Vector3((Math.random()-0.3)*30, (Math.random()-0.5)*18, (Math.random()-0.5)*14),
      v: new THREE.Vector3((Math.random()-0.5)*0.006, (Math.random()-0.5)*0.006, (Math.random()-0.5)*0.006),
      sig: Math.random() < 0.18,
    });
  }
  const nodeGeom = new THREE.BufferGeometry();
  const nodePos  = new Float32Array(NODES*3);
  const nodeCol  = new Float32Array(NODES*3);
  const nodeSz   = new Float32Array(NODES);
  for (let i=0;i<NODES;i++){
    const n=nodes[i];
    nodePos[i*3]=n.p.x; nodePos[i*3+1]=n.p.y; nodePos[i*3+2]=n.p.z;
    if(n.sig){ nodeCol[i*3]=1.4; nodeCol[i*3+1]=1.9; nodeCol[i*3+2]=0.5; nodeSz[i]=8; }
    else      { nodeCol[i*3]=0.9; nodeCol[i*3+1]=0.9; nodeCol[i*3+2]=0.9; nodeSz[i]=3.2; }
  }
  nodeGeom.setAttribute('position', new THREE.BufferAttribute(nodePos,3));
  nodeGeom.setAttribute('color', new THREE.BufferAttribute(nodeCol,3));
  nodeGeom.setAttribute('size', new THREE.BufferAttribute(nodeSz,1));

  // PointsNodeMaterial: round, additive, vertex-coloured, size-attenuated
  const nodeMat = new THREE.PointsNodeMaterial({
    transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
    vertexColors: true, sizeAttenuation: true,
  });
  try {
    const { attribute, positionView, float } = TSL;
    nodeMat.sizeNode = attribute('size').mul(float(320).div(positionView.z.negate().max(0.001)));
  } catch (e) { /* keep default look if TSL attrs differ */ }
  const nodeMesh = new THREE.Points(nodeGeom, nodeMat);
  scene.add(nodeMesh);

  /* ---------- CONNECTION LINES ---------- */
  const MAX_LINES = NODES*4;
  const linePos = new Float32Array(MAX_LINES*2*3);
  const lineCol = new Float32Array(MAX_LINES*2*3);
  const lineGeom = new THREE.BufferGeometry();
  lineGeom.setAttribute('position', new THREE.BufferAttribute(linePos,3));
  lineGeom.setAttribute('color', new THREE.BufferAttribute(lineCol,3));
  const lineMat = new THREE.LineBasicNodeMaterial({ vertexColors:true, transparent:true, opacity:0.55, blending:THREE.AdditiveBlending });
  const lineMesh = new THREE.LineSegments(lineGeom, lineMat);
  scene.add(lineMesh);

  /* ---------- PACKETS ---------- */
  const PACKETS = 44;
  const packets = [];
  const pkPos = new Float32Array(PACKETS*3);
  const pkGeom = new THREE.BufferGeometry();
  pkGeom.setAttribute('position', new THREE.BufferAttribute(pkPos,3));
  const pkMat = new THREE.PointsNodeMaterial({ color:0xC7F23E, size:6, transparent:true, blending:THREE.AdditiveBlending, depthWrite:false, sizeAttenuation:true });
  const pkMesh = new THREE.Points(pkGeom, pkMat);
  scene.add(pkMesh);
  for(let i=0;i<PACKETS;i++) packets.push({a:0,b:1,t:Math.random(),speed:0.003+Math.random()*0.008});

  /* ---------- ambient rings (depth) ---------- */
  const ringMat = new THREE.MeshBasicNodeMaterial({ color:0xC7F23E, transparent:true, opacity:0.06, side:THREE.DoubleSide });
  const ring1 = new THREE.Mesh(new THREE.RingGeometry(28,28.2,128), ringMat); ring1.position.z=-8; scene.add(ring1);
  const ring2 = new THREE.Mesh(new THREE.RingGeometry(22,22.15,128), ringMat.clone()); ring2.position.z=-12; ring2.material.opacity=0.04; scene.add(ring2);

  /* =================================================================
     POST-PROCESSING — pass → bloom → (chromatic aberration + grain)
     ================================================================= */
  let post = null;
  try {
    const { pass, uniform, float, vec2, vec3, vec4, screenUV, time, Fn } = TSL;
    const { bloom } = await import('three/addons/tsl/display/BloomNode.js');

    post = new THREE.PostProcessing(renderer);
    const scenePass = pass(scene, cam);
    const color = scenePass.getTextureNode();

    const bloomPass = bloom(color, 0.9, 0.5, 0.0);

    // cursor-velocity flowmap → drives aberration amount + direction
    const uAberr = uniform(0.0);          // velocity 0..1
    const uDir   = uniform(new THREE.Vector2(0, 0));
    post._uAberr = uAberr; post._uDir = uDir;

    const compose = Fn(() => {
      const suv = screenUV;
      // directional offset = base radial + cursor-driven directional
      const radial = suv.sub(vec2(0.5, 0.5));
      const amt = float(0.0016).add(uAberr.mul(0.01));
      const dirOff = vec2(uDir.x, uDir.y).mul(amt.mul(1.4));
      const oR = radial.mul(amt.mul(1.6)).add(dirOff.mul(1.5));
      const oB = radial.mul(amt.mul(1.6)).add(dirOff.mul(1.8)).negate();
      const r = color.sample(suv.add(oR)).r;
      const g = color.sample(suv).g;
      const b = color.sample(suv.add(oB)).b;
      let col = vec3(r, g, b);
      // film grain
      const n = suv.add(time.mul(0.5)).mul(vec2(1213.0, 871.0));
      const grain = n.x.add(n.y).sin().mul(43758.5453).fract();
      col = col.add(vec3(grain.sub(0.5)).mul(0.05));
      return vec4(col, 1.0);
    });

    post.outputNode = compose().add(bloomPass);
    post._hasPost = true;
  } catch (e) {
    console.warn('[tsm-engine] post-processing degraded → bloom/plain', e);
    post = null;
  }

  /* =================================================================
     IDLE GUARD — suspend loop after 90 frames of no input
     ================================================================= */
  const idle = { frames: 0, running: true };
  const wake = () => { idle.frames = 0; if (!idle.running) { idle.running = true; loop(); } };
  ['pointermove','pointerdown','wheel','scroll','touchmove','keydown'].forEach(ev =>
    addEventListener(ev, wake, { passive: true }));

  /* ---------- main loop ---------- */
  const tmp = new THREE.Vector3();
  let t = 0;
  function frame() {
    t += 1/60;

    for (let i=0;i<NODES;i++){
      const n=nodes[i];
      n.p.add(n.v);
      if(n.p.x>16||n.p.x<-16)n.v.x*=-1;
      if(n.p.y>9||n.p.y<-9)n.v.y*=-1;
      if(n.p.z>7||n.p.z<-7)n.v.z*=-1;
      nodePos[i*3]=n.p.x; nodePos[i*3+1]=n.p.y; nodePos[i*3+2]=n.p.z;
    }
    nodeGeom.attributes.position.needsUpdate = true;

    let lc=0; const edges=[];
    for(let i=0;i<NODES;i++)for(let j=i+1;j<NODES;j++){
      const a=nodes[i].p,b=nodes[j].p;
      const dx=a.x-b.x,dy=a.y-b.y,dz=a.z-b.z,d2=dx*dx+dy*dy+dz*dz;
      if(d2<24&&lc<MAX_LINES){
        const al=1-d2/24, sig=nodes[i].sig||nodes[j].sig, c=sig?[1.0,1.3,0.34]:[0.5,0.5,0.5];
        linePos[lc*6]=a.x;linePos[lc*6+1]=a.y;linePos[lc*6+2]=a.z;
        linePos[lc*6+3]=b.x;linePos[lc*6+4]=b.y;linePos[lc*6+5]=b.z;
        for(let s=0;s<2;s++){lineCol[lc*6+s*3]=c[0]*al;lineCol[lc*6+s*3+1]=c[1]*al;lineCol[lc*6+s*3+2]=c[2]*al;}
        edges.push([i,j]); lc++;
      }
    }
    for(let k=lc;k<MAX_LINES;k++)for(let s=0;s<6;s++){linePos[k*6+s]=0;lineCol[k*6+s]=0;}
    lineGeom.attributes.position.needsUpdate=true;
    lineGeom.attributes.color.needsUpdate=true;
    lineGeom.setDrawRange(0,lc*2);

    for(let i=0;i<PACKETS;i++){
      const pk=packets[i]; pk.t+=pk.speed;
      if(pk.t>=1||!edges[pk._e??-1]){const idx=Math.floor(Math.random()*Math.max(1,edges.length));if(edges[idx]){pk.a=edges[idx][0];pk.b=edges[idx][1];pk._e=idx;pk.t=0;}}
      tmp.lerpVectors(nodes[pk.a].p,nodes[pk.b].p,pk.t);
      pkPos[i*3]=tmp.x;pkPos[i*3+1]=tmp.y;pkPos[i*3+2]=tmp.z;
    }
    pkGeom.attributes.position.needsUpdate=true;

    // camera parallax + drift
    cam.position.x += ((ptr.x-0.5)*4 + Math.sin(t*0.12)*0.5 - cam.position.x)*0.02;
    cam.position.y += (-(ptr.y-0.5)*2.4 + Math.cos(t*0.09)*0.3 - cam.position.y)*0.02;
    cam.position.z = 22 + Math.sin(t*0.06)*0.6;
    cam.lookAt(0,0,0);
    nodeMesh.rotation.y = Math.sin(t*0.05)*0.06;
    lineMesh.rotation.y = nodeMesh.rotation.y;
    pkMesh.rotation.y = nodeMesh.rotation.y;
    ring1.rotation.z = t*0.04; ring2.rotation.z = -t*0.03;

    // flowmap → aberration uniforms (decay velocity)
    ptr.vel *= 0.92;
    if (post && post._uAberr) { post._uAberr.value = ptr.vel; post._uDir.value.set(ptr.vx*20, -ptr.vy*20); }

    if (post && post._hasPost) post.render();
    else renderer.render(scene, cam);
  }

  function loop() {
    if (!idle.running) return;
    frame();
    idle.frames++;
    if (idle.frames >= 90 && performance.now() - ptr.moved > 1500) { idle.running = false; return; }
    requestAnimationFrame(loop);
  }
  loop();
  // keep it alive briefly even without input so it's visibly animating on load
  setTimeout(wake, 100);

  return engineMode;
}

/* =====================================================================
   CANVAS-2D FALLBACK — drifting node field (always works)
   ===================================================================== */
function fallback2D() {
  engineMode = 'canvas2d';
  if (!container) return;
  const canvas = document.createElement('canvas');
  Object.assign(canvas.style, { width:'100%', height:'100%', display:'block' });
  container.appendChild(canvas);
  const ctx = canvas.getContext('2d');
  const DPR = Math.min(devicePixelRatio||1, 2);
  let W=0,H=0;
  const resize=()=>{const r=container.getBoundingClientRect();W=r.width;H=r.height;canvas.width=W*DPR;canvas.height=H*DPR;ctx.setTransform(DPR,0,0,DPR,0,0);};
  resize(); addEventListener('resize', resize);
  const N=64, nodes=[];
  for(let i=0;i<N;i++)nodes.push({x:Math.random(),y:Math.random(),vx:(Math.random()-0.5)*0.0006,vy:(Math.random()-0.5)*0.0006,sig:Math.random()<0.18});
  function draw(){
    ctx.fillStyle='rgba(5,5,5,0.28)';ctx.fillRect(0,0,W,H);
    for(const n of nodes){n.x+=n.vx;n.y+=n.vy;if(n.x<0||n.x>1)n.vx*=-1;if(n.y<0||n.y>1)n.vy*=-1;}
    for(let i=0;i<N;i++)for(let j=i+1;j<N;j++){
      const a=nodes[i],b=nodes[j],dx=(a.x-b.x)*W,dy=(a.y-b.y)*H,d=Math.hypot(dx,dy);
      if(d<170){const al=(1-d/170)*0.5,sig=a.sig||b.sig;ctx.strokeStyle=sig?`rgba(199,242,62,${al})`:`rgba(140,140,140,${al*0.6})`;ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(a.x*W,a.y*H);ctx.lineTo(b.x*W,b.y*H);ctx.stroke();}
    }
    for(const n of nodes){ctx.fillStyle=n.sig?'#C7F23E':'#D9D9D9';const s=n.sig?4:2;ctx.fillRect(n.x*W-s/2,n.y*H-s/2,s,s);}
    requestAnimationFrame(draw);
  }
  draw();
}

/* boot */
initWebGPU()
  .then(mode => { window.__tsmEngine = mode; console.log('[tsm-engine] running:', mode); })
  .catch(err => { console.warn('[tsm-engine] WebGPU/TSL unavailable → canvas2d fallback', err); try { fallback2D(); } catch(e){} window.__tsmEngine = 'canvas2d'; });
