"""Three.js welcome scene for the Red Team Console landing page."""


def render_welcome_scene(height: int = 500) -> str:
    """Return HTML embedding a WebGL Three.js icosahedron hero scene."""
    return f"""
    <div id="scene-container" style="width:100%; height:{height}px;
         position:relative; overflow:hidden;
         background: radial-gradient(circle at center, #0d1410 0%, #08090a 70%);">
      <canvas id="three-canvas" style="display:block; width:100%;
              height:100%;"></canvas>
    </div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/shaders/CopyShader.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/postprocessing/Pass.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/postprocessing/ShaderPass.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/shaders/LuminosityHighPassShader.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/postprocessing/EffectComposer.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/postprocessing/RenderPass.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/postprocessing/UnrealBloomPass.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/lines/LineMaterial.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/lines/LineGeometry.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/lines/LineSegmentsGeometry.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/lines/LineSegments2.js"></script>
    <script>
    (function() {{
      const container = document.getElementById('scene-container');
      const canvas = document.getElementById('three-canvas');

      const scene = new THREE.Scene();
      const camera = new THREE.PerspectiveCamera(
        45, container.clientWidth / container.clientHeight, 0.1, 1000
      );
      camera.position.set(0, 0, 5.5);

      const renderer = new THREE.WebGLRenderer({{
        canvas: canvas, antialias: true, alpha: true
      }});
      renderer.setClearColor(0x000000, 0);
      renderer.setSize(container.clientWidth, container.clientHeight);
      renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

      let composer = null;
      if (typeof THREE.EffectComposer !== 'undefined'
          && typeof THREE.UnrealBloomPass !== 'undefined') {{
        const renderScene = new THREE.RenderPass(scene, camera);
        const bloomPass = new THREE.UnrealBloomPass(
          new THREE.Vector2(container.clientWidth, container.clientHeight),
          1.4,
          0.6,
          0.15
        );
        composer = new THREE.EffectComposer(renderer);
        composer.addPass(renderScene);
        composer.addPass(bloomPass);
      }}

      const keyLight = new THREE.PointLight(0xff4d4d, 2.5, 20);
      keyLight.position.set(3, 2, 3);
      scene.add(keyLight);

      const fillLight = new THREE.PointLight(0x3ddc84, 1.2, 20);
      fillLight.position.set(-3, -2, 2);
      scene.add(fillLight);

      const ambient = new THREE.AmbientLight(0x222233, 0.6);
      scene.add(ambient);

      const outerGeo = new THREE.IcosahedronGeometry(1.3, 0);

      const outerSolid = new THREE.Mesh(outerGeo, new THREE.MeshStandardMaterial({{
        color: 0x1a0808, metalness: 0.3, roughness: 0.4,
        transparent: true, opacity: 0.15
      }}));

      const edgesGeo = new THREE.EdgesGeometry(outerGeo);
      let wireMat = null;
      let outerWire;
      if (typeof THREE.LineSegments2 !== 'undefined') {{
        const wireGeo = new THREE.LineSegmentsGeometry();
        wireGeo.setPositions(edgesGeo.attributes.position.array);
        wireMat = new THREE.LineMaterial({{
          color: 0xff0033,
          linewidth: 3.5,
          transparent: true,
          opacity: 1.0,
          depthTest: true,
          blending: THREE.AdditiveBlending
        }});
        wireMat.resolution.set(container.clientWidth, container.clientHeight);
        outerWire = new THREE.LineSegments2(wireGeo, wireMat);
        outerWire.computeLineDistances();
      }} else {{
        outerWire = new THREE.LineSegments(edgesGeo, new THREE.LineBasicMaterial({{
          color: 0xff0033, transparent: true, opacity: 1.0
        }}));
      }}

      const innerGeo = new THREE.IcosahedronGeometry(0.65, 1);
      const innerMat = new THREE.MeshStandardMaterial({{
        color: 0x3ddc84, emissive: 0x1a6b3f, emissiveIntensity: 1.4,
        metalness: 0.4, roughness: 0.3,
        transparent: true, opacity: 0.55
      }});
      const innerMesh = new THREE.Mesh(innerGeo, innerMat);

      const shapeGroup = new THREE.Group();
      shapeGroup.add(outerSolid, outerWire, innerMesh);
      scene.add(shapeGroup);

      const particleCount = 350;
      const positions = new Float32Array(particleCount * 3);
      for (let i = 0; i < particleCount; i++) {{
        const radius = 3 + Math.random() * 5;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.random() * Math.PI;
        positions[i * 3] = radius * Math.sin(phi) * Math.cos(theta);
        positions[i * 3 + 1] = radius * Math.sin(phi) * Math.sin(theta);
        positions[i * 3 + 2] = radius * Math.cos(phi);
      }}
      const particleGeo = new THREE.BufferGeometry();
      particleGeo.setAttribute('position',
        new THREE.BufferAttribute(positions, 3));
      const particleMat = new THREE.PointsMaterial({{
        color: 0x9ca3af, size: 0.035, transparent: true, opacity: 0.7,
        sizeAttenuation: true
      }});
      const particles = new THREE.Points(particleGeo, particleMat);
      scene.add(particles);

      const trailCount = 60;
      const trailPositions = new Float32Array(trailCount * 3);
      const trailGeo = new THREE.BufferGeometry();
      trailGeo.setAttribute('position',
        new THREE.BufferAttribute(trailPositions, 3));

      const trailMat = new THREE.PointsMaterial({{
        color: 0xff2244, size: 0.05, transparent: true, opacity: 0.8,
        blending: THREE.AdditiveBlending, depthWrite: false
      }});
      const trail = new THREE.Points(trailGeo, trailMat);
      scene.add(trail);

      let trailIndex = 0;

      function spawnTrailParticle() {{
        const vertices = outerGeo.attributes.position;
        const vIdx = Math.floor(Math.random() * vertices.count);
        const vx = vertices.getX(vIdx);
        const vy = vertices.getY(vIdx);
        const vz = vertices.getZ(vIdx);

        const i3 = trailIndex * 3;
        trailPositions[i3] = vx + (Math.random() - 0.5) * 0.15;
        trailPositions[i3 + 1] = vy + (Math.random() - 0.5) * 0.15;
        trailPositions[i3 + 2] = vz + (Math.random() - 0.5) * 0.15;

        trailIndex = (trailIndex + 1) % trailCount;
        trailGeo.attributes.position.needsUpdate = true;
      }}

      let mouseX = 0, mouseY = 0;
      let targetRotX = 0, targetRotY = 0;

      container.addEventListener('mousemove', (e) => {{
        const rect = container.getBoundingClientRect();
        mouseX = ((e.clientX - rect.left) / rect.width) * 2 - 1;
        mouseY = ((e.clientY - rect.top) / rect.height) * 2 - 1;
      }});

      const clock = new THREE.Clock();
      let frameCount = 0;

      function animate() {{
        requestAnimationFrame(animate);
        const t = clock.getElapsedTime();

        shapeGroup.rotation.y += 0.0035;
        innerMesh.rotation.y -= 0.006;
        innerMesh.rotation.x -= 0.002;

        const pulse = 1 + Math.sin(t * 0.8) * 0.03;
        innerMesh.scale.set(pulse, pulse, pulse);

        targetRotX += (mouseY * 0.5 - targetRotX) * 0.04;
        targetRotY += (mouseX * 0.5 - targetRotY) * 0.04;
        shapeGroup.rotation.x = targetRotX * 0.4;
        shapeGroup.rotation.z = targetRotY * 0.15;

        keyLight.position.x = Math.sin(t * 0.3) * 4;
        keyLight.position.z = Math.cos(t * 0.3) * 4;

        particles.rotation.y += 0.0006;

        frameCount++;
        if (frameCount % 4 === 0) {{
          spawnTrailParticle();
        }}
        trail.rotation.copy(shapeGroup.rotation);

        if (composer) {{
          composer.render();
        }} else {{
          renderer.render(scene, camera);
        }}
      }}
      animate();

      window.addEventListener('resize', () => {{
        camera.aspect = container.clientWidth / container.clientHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(container.clientWidth, container.clientHeight);
        if (composer) {{
          composer.setSize(container.clientWidth, container.clientHeight);
        }}
        if (wireMat) {{
          wireMat.resolution.set(container.clientWidth, container.clientHeight);
        }}
      }});
    }})();
    </script>
    """
