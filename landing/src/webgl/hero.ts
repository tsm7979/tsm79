/* ============================================================================
   Hero WebGL — "The Sovereign Core" (cinematic)
   A faceted glass monolith (Blender-authored, public/models/core.glb) with an
   inner light it refracts across its facets. Curl-noise particle streams — the
   inspected prompts — funnel through an inspection waist and are classified by
   colour (pale=pass, amber=redact, terracotta=block). Rendered through a
   cinematic composer: selective bloom + depth-of-field + film grain + vignette
   + subtle chromatic aberration, ACES tone-mapped and dark. Real GPU only.
   ========================================================================== */
import * as THREE from "three";
import { GLTFLoader } from "three/examples/jsm/loaders/GLTFLoader.js";
import { RoomEnvironment } from "three/examples/jsm/environments/RoomEnvironment.js";
import {
  EffectComposer, RenderPass, EffectPass, BloomEffect, DepthOfFieldEffect,
  NoiseEffect, VignetteEffect, ChromaticAberrationEffect, ToneMappingEffect,
  ToneMappingMode, BlendFunction, KernelSize, SMAAEffect,
} from "postprocessing";

const SAGE = new THREE.Color(0.71, 0.77, 0.70);
const PALE = new THREE.Color(0.92, 0.91, 0.85);
const AMBER = new THREE.Color(0.86, 0.66, 0.36);
const TERRA = new THREE.Color(0.86, 0.43, 0.36);

const SNOISE = /* glsl */ `
vec4 permute(vec4 x){return mod(((x*34.0)+1.0)*x,289.0);}
vec4 taylorInvSqrt(vec4 r){return 1.79284291400159-0.85373472095314*r;}
float snoise(vec3 v){
  const vec2 C=vec2(1.0/6.0,1.0/3.0); const vec4 D=vec4(0.0,0.5,1.0,2.0);
  vec3 i=floor(v+dot(v,C.yyy)); vec3 x0=v-i+dot(i,C.xxx);
  vec3 g=step(x0.yzx,x0.xyz); vec3 l=1.0-g; vec3 i1=min(g.xyz,l.zxy); vec3 i2=max(g.xyz,l.zxy);
  vec3 x1=x0-i1+C.xxx; vec3 x2=x0-i2+2.0*C.xxx; vec3 x3=x0-1.0+3.0*C.xxx;
  i=mod(i,289.0);
  vec4 p=permute(permute(permute(i.z+vec4(0.0,i1.z,i2.z,1.0))+i.y+vec4(0.0,i1.y,i2.y,1.0))+i.x+vec4(0.0,i1.x,i2.x,1.0));
  float n_=1.0/7.0; vec3 ns=n_*D.wyz-D.xzx;
  vec4 j=p-49.0*floor(p*ns.z*ns.z); vec4 x_=floor(j*ns.z); vec4 y_=floor(j-7.0*x_);
  vec4 x=x_*ns.x+ns.yyyy; vec4 y=y_*ns.x+ns.yyyy; vec4 h=1.0-abs(x)-abs(y);
  vec4 b0=vec4(x.xy,y.xy); vec4 b1=vec4(x.zw,y.zw);
  vec4 s0=floor(b0)*2.0+1.0; vec4 s1=floor(b1)*2.0+1.0; vec4 sh=-step(h,vec4(0.0));
  vec4 a0=b0.xzyw+s0.xzyw*sh.xxyy; vec4 a1=b1.xzyw+s1.xzyw*sh.zzww;
  vec3 p0=vec3(a0.xy,h.x); vec3 p1=vec3(a0.zw,h.y); vec3 p2=vec3(a1.xy,h.z); vec3 p3=vec3(a1.zw,h.w);
  vec4 norm=taylorInvSqrt(vec4(dot(p0,p0),dot(p1,p1),dot(p2,p2),dot(p3,p3)));
  p0*=norm.x;p1*=norm.y;p2*=norm.z;p3*=norm.w;
  vec4 m=max(0.6-vec4(dot(x0,x0),dot(x1,x1),dot(x2,x2),dot(x3,x3)),0.0); m=m*m;
  return 42.0*dot(m*m,vec4(dot(p0,x0),dot(p1,x1),dot(p2,x2),dot(p3,x3)));
}`;

export function initHero(canvas: HTMLCanvasElement, onReady?: () => void) {
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const wide = () => innerWidth > 900;
  const mobile = innerWidth < 760;

  const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: false, powerPreference: "high-performance" });
  renderer.setPixelRatio(Math.min(devicePixelRatio, mobile ? 1.3 : 1.6));
  renderer.setSize(innerWidth, innerHeight);
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 0.92;

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(42, innerWidth / innerHeight, 0.1, 100);
  camera.position.set(0, 0, 6.6);

  const pmrem = new THREE.PMREMGenerator(renderer);
  scene.environment = pmrem.fromScene(new RoomEnvironment(), 0.04).texture;

  const group = new THREE.Group();
  scene.add(group);
  const place = () => {
    group.position.set(0, wide() ? 0.3 : 0.5, 0);   // centered behind the centered headline
    group.scale.setScalar(wide() ? 1.0 : 0.66);
  };
  place();

  // ── inner light: the sovereign core's energy (refracted by the glass) ──
  const innerUni = { uTime: { value: 0 } };
  const inner = new THREE.Mesh(
    new THREE.IcosahedronGeometry(0.62, 6),
    new THREE.ShaderMaterial({
      uniforms: innerUni,
      vertexShader: `${SNOISE}
        uniform float uTime; varying float vN;
        void main(){
          float n = snoise(normalize(position)*2.2 + uTime*0.25);
          vN = n;
          vec3 p = position + normal * n * 0.12;
          gl_Position = projectionMatrix * modelViewMatrix * vec4(p,1.0);
        }`,
      fragmentShader: `
        varying float vN;
        void main(){
          vec3 a = vec3(0.42,0.52,0.42); vec3 b = vec3(0.95,0.93,0.82);
          gl_FragColor = vec4(mix(a,b, smoothstep(-0.4,0.6,vN)) * 1.4, 1.0);
        }`,
    })
  );
  group.add(inner);

  // ── outer faceted glass shell (refracts the inner light + environment) ──
  let glass: THREE.Mesh | undefined;
  const glassMat = new THREE.MeshPhysicalMaterial({
    color: new THREE.Color(0.04, 0.05, 0.045),
    metalness: 0, roughness: 0.06, transmission: 1, thickness: 2.2, ior: 1.55,
    clearcoat: 1, clearcoatRoughness: 0.12, envMapIntensity: 0.7,
    attenuationColor: new THREE.Color(0.30, 0.42, 0.36), attenuationDistance: 1.4,
    transparent: true,
  });
  new GLTFLoader().load("/models/core.glb", (g) => {
    g.scene.traverse((o) => {
      const m = o as THREE.Mesh;
      if (m.isMesh) {
        const box = new THREE.Box3().setFromObject(m);
        const r = box.getBoundingSphere(new THREE.Sphere()).radius || 1;
        m.material = glassMat; m.scale.setScalar(1.55 / r); m.geometry.center();
        glass = m; group.add(m);
      }
    });
    onReady?.();
  }, undefined, () => onReady?.());

  // ── inspection particle streams (funnel through the waist at x=0) ──
  const N = mobile ? 3500 : 5500;
  const seed = new Float32Array(N * 3), type = new Float32Array(N), size = new Float32Array(N);
  for (let i = 0; i < N; i++) {
    seed[i * 3] = Math.random(); seed[i * 3 + 1] = Math.random(); seed[i * 3 + 2] = Math.random();
    const r = Math.random(); type[i] = r > 0.92 ? 2 : r > 0.7 ? 1 : 0;
    size[i] = 0.6 + Math.random() * 1.1;
  }
  const pg = new THREE.BufferGeometry();
  pg.setAttribute("position", new THREE.BufferAttribute(new Float32Array(N * 3), 3)); // unused; pos in shader
  pg.setAttribute("aSeed", new THREE.BufferAttribute(seed, 3));
  pg.setAttribute("aType", new THREE.BufferAttribute(type, 1));
  pg.setAttribute("aSize", new THREE.BufferAttribute(size, 1));
  const pUni = { uTime: { value: 0 }, uPr: { value: renderer.getPixelRatio() } };
  const particles = new THREE.Points(pg, new THREE.ShaderMaterial({
    uniforms: pUni, transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
    vertexShader: `${SNOISE}
      attribute vec3 aSeed; attribute float aType; attribute float aSize;
      uniform float uTime; uniform float uPr;
      varying vec3 vCol; varying float vA;
      void main(){
        float speed = 0.045 + aSeed.y*0.05;
        float p = fract(aSeed.x + uTime*speed);
        float x = mix(-5.5, 4.0, p);
        float waist = exp(-x*x/1.6);                 // 1 at the inspection seam (x=0)
        float width = mix(1.9, 0.36, waist);
        vec3 base = vec3(x, (aSeed.y-0.5)*2.0*width, (aSeed.z-0.5)*2.0*width);
        vec3 sw = vec3(snoise(base*0.45+uTime*0.05), snoise(base*0.45+9.0), snoise(base*0.45-9.0+uTime*0.05));
        vec3 pos = base + sw * mix(0.7,0.18,waist);
        vCol = PALE_C;
        if (x > 0.05){ vCol = aType>1.5?TERRA_C : aType>0.5?AMBER_C : SAGE_C; }
        if (aType>1.5 && x>0.4){ pos.y -= (x*x)*0.06; pos.z += x*0.12; }  // blocked peel-off
        vA = smoothstep(0.0,0.08,p) * (1.0 - smoothstep(0.82,1.0,p));
        vec4 mv = modelViewMatrix * vec4(pos,1.0);
        gl_PointSize = aSize * uPr * (105.0 / -mv.z) * mix(0.6,1.2,waist);
        gl_Position = projectionMatrix * mv;
      }`
      .replace("PALE_C", `vec3(${PALE.r},${PALE.g},${PALE.b})`)
      .replace("SAGE_C", `vec3(${SAGE.r},${SAGE.g},${SAGE.b})`)
      .replace("AMBER_C", `vec3(${AMBER.r},${AMBER.g},${AMBER.b})`)
      .replace("TERRA_C", `vec3(${TERRA.r},${TERRA.g},${TERRA.b})`),
    fragmentShader: `
      varying vec3 vCol; varying float vA;
      void main(){
        float d = length(gl_PointCoord-0.5); if(d>0.5) discard;
        gl_FragColor = vec4(vCol*0.8, smoothstep(0.5,0.06,d) * vA * 0.3);
      }`,
  }));
  particles.frustumCulled = false;
  group.add(particles);

  // ── inspection seam ──
  const seam = new THREE.Line(
    new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(0, -3, 0), new THREE.Vector3(0, 3, 0)]),
    new THREE.LineBasicMaterial({ color: 0xb7c0b3, transparent: true, opacity: 0.18 })
  );
  group.add(seam);

  // ── cinematic composer ──
  const composer = new EffectComposer(renderer, { frameBufferType: THREE.HalfFloatType });
  composer.addPass(new RenderPass(scene, camera));
  const bloom = new BloomEffect({ intensity: 0.62, luminanceThreshold: 0.8, luminanceSmoothing: 0.35, mipmapBlur: true, radius: 0.68, kernelSize: KernelSize.HUGE });
  const dof = new DepthOfFieldEffect(camera, { focusDistance: 0.0, focalLength: 0.03, bokehScale: 1.1 });
  const noise = new NoiseEffect({ blendFunction: BlendFunction.OVERLAY }); (noise as any).blendMode.opacity.value = 0.14;
  const vignette = new VignetteEffect({ offset: 0.28, darkness: 0.82 });
  const tone = new ToneMappingEffect({ mode: ToneMappingMode.ACES_FILMIC });
  const ca = new ChromaticAberrationEffect({ offset: new THREE.Vector2(0.0009, 0.0009), radialModulation: true, modulationOffset: 0.4 });
  composer.addPass(new EffectPass(camera, dof));
  composer.addPass(new EffectPass(camera, bloom));
  composer.addPass(new EffectPass(camera, vignette, noise, tone));
  composer.addPass(new EffectPass(camera, ca));
  if (!mobile) composer.addPass(new EffectPass(camera, new SMAAEffect()));

  // ── interaction / loop ──
  const tgt = new THREE.Vector2(), cur = new THREE.Vector2();
  addEventListener("mousemove", (e) => tgt.set((e.clientX / innerWidth - 0.5) * 2, -(e.clientY / innerHeight - 0.5) * 2));
  let paused = false; const dimmed = () => canvas.classList.contains("is-dim");
  document.addEventListener("visibilitychange", () => (paused = document.hidden));
  const clock = new THREE.Clock();

  function tick() {
    requestAnimationFrame(tick);
    if (paused || dimmed()) return;
    const t = clock.getElapsedTime();
    cur.lerp(tgt, 0.045);
    innerUni.uTime.value = t; pUni.uTime.value = t;
    if (glass) { glass.rotation.y = t * 0.12; glass.rotation.x = Math.sin(t * 0.18) * 0.12; }
    inner.rotation.y = -t * 0.08;
    group.rotation.y = cur.x * 0.14; group.rotation.x = -cur.y * 0.08;
    camera.position.x += (cur.x * 0.5 - camera.position.x) * 0.04;
    camera.position.y += (cur.y * 0.3 - camera.position.y) * 0.04;
    camera.lookAt(0, group.position.y * 0.5, 0);
    seam.material.opacity = 0.12 + 0.08 * Math.abs(Math.sin(t * 1.3));
    composer.render();
  }
  tick();
  if (reduced) paused = true;

  // ── WebGL context-loss recovery: a GPU reset must not leave the centrepiece
  //    frozen black. preventDefault lets the browser restore; then we rebuild
  //    the sized targets and resume the loop (Three re-uploads GPU resources).
  canvas.addEventListener("webglcontextlost", (e) => { e.preventDefault(); paused = true; }, false);
  canvas.addEventListener("webglcontextrestored", () => {
    renderer.setSize(innerWidth, innerHeight);
    composer.setSize(innerWidth, innerHeight);
    pUni.uPr.value = renderer.getPixelRatio();
    if (!reduced) paused = false;
  }, false);

  addEventListener("resize", () => {
    camera.aspect = innerWidth / innerHeight; camera.updateProjectionMatrix();
    renderer.setSize(innerWidth, innerHeight); composer.setSize(innerWidth, innerHeight);
    pUni.uPr.value = renderer.getPixelRatio(); place();
  });
}
