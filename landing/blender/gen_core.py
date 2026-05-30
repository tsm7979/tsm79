# Procedural "Sovereign Core" — a faceted crystalline monolith built for
# real-time REFRACTION in three.js (MeshPhysicalMaterial transmission).
# Clean planar facets (like cut obsidian) refract cleanly; noisy spikes do not.
# Run headless:  blender --background --python gen_core.py
# Outputs: ../public/models/core.glb  +  preview.png
import bpy, bmesh, os, math
from mathutils import noise, Vector

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_GLB = os.path.normpath(os.path.join(HERE, "..", "public", "models", "core.glb"))
OUT_PNG = os.path.join(HERE, "preview.png")
os.makedirs(os.path.dirname(OUT_GLB), exist_ok=True)

# ── clean scene ──
bpy.ops.object.select_all(action="SELECT")
bpy.ops.object.delete(use_global=False)
for blk in (bpy.data.meshes, bpy.data.materials):
    for b in list(blk):
        blk.remove(b)

# ── base: medium icosphere → big planar facets (a cut gem, not a noisy ball) ──
bpy.ops.mesh.primitive_ico_sphere_add(subdivisions=3, radius=1.4)
obj = bpy.context.active_object
obj.name = "SovereignCore"
me = obj.data

bm = bmesh.new(); bm.from_mesh(me)
bm.normal_update()
SEED = Vector((12.3, 4.7, 8.1))
for v in bm.verts:
    d = v.co.normalized()
    # low-frequency carve → an asymmetric monolith silhouette (not a sphere)
    carve = noise.noise(d * 1.15 + SEED) * 0.30 + noise.noise(d * 2.1 - SEED) * 0.12
    # gentle vertical elongation → standing crystal
    elong = 1.0 + d.z * 0.18
    v.co = v.co * elong + v.normal * carve
bm.normal_update()
# planarise facets a touch so each triangle reads as a flat cut face
bm.to_mesh(me); bm.free()

# sharp faceted shading (flat) — the cut-crystal read
for p in me.polygons:
    p.use_smooth = False
me.update()

# ── material (placeholder; three.js overrides with a glass/physical material) ──
mat = bpy.data.materials.new("core")
mat.use_nodes = True
bsdf = mat.node_tree.nodes.get("Principled BSDF")
bsdf.inputs["Base Color"].default_value = (0.02, 0.022, 0.02, 1.0)
bsdf.inputs["Roughness"].default_value = 0.18
bsdf.inputs["Metallic"].default_value = 0.0
try: bsdf.inputs["Transmission Weight"].default_value = 0.9
except Exception:
    try: bsdf.inputs["Transmission"].default_value = 0.9
    except Exception: pass
obj.data.materials.append(mat)

# ── preview render (sanity check only; does not affect the export) ──
scene = bpy.context.scene
try: scene.render.engine = "BLENDER_EEVEE_NEXT"
except Exception: scene.render.engine = "BLENDER_EEVEE"
scene.render.resolution_x = 900; scene.render.resolution_y = 900
world = bpy.data.worlds["World"]; world.use_nodes = True
world.node_tree.nodes["Background"].inputs[0].default_value = (0.015, 0.015, 0.014, 1.0)

cam_data = bpy.data.cameras.new("cam"); cam = bpy.data.objects.new("cam", cam_data)
scene.collection.objects.link(cam); scene.camera = cam
cam.location = (0, -4.6, 1.2); cam.rotation_euler = (math.radians(78), 0, 0)
cam_data.lens = 70

def add_light(name, loc, energy, size, color):
    ld = bpy.data.lights.new(name, "AREA"); ld.energy = energy; ld.size = size; ld.color = color
    o = bpy.data.objects.new(name, ld); o.location = loc
    o.rotation_euler = (math.radians(55), 0, math.radians(35))
    scene.collection.objects.link(o); return o
add_light("key", (3.2, -3.0, 4.0), 1100, 6.0, (1.0, 0.96, 0.88))
add_light("rim", (-3.5, 2.0, 2.0), 520, 5.0, (0.72, 0.78, 0.74))
scene.render.filepath = OUT_PNG
bpy.ops.render.render(write_still=True)
print("RENDERED", OUT_PNG)

# ── export glb ──
bpy.ops.object.select_all(action="DESELECT")
obj.select_set(True); bpy.context.view_layer.objects.active = obj
bpy.ops.export_scene.gltf(
    filepath=OUT_GLB, export_format="GLB", use_selection=True,
    export_draco_mesh_compression_enable=False, export_apply=True,
)
print("EXPORTED", OUT_GLB, "tris:", len(me.polygons))
