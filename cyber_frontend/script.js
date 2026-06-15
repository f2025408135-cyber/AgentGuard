document.addEventListener('DOMContentLoaded', () => {

    // Typing Effect for specific elements (optional addition)
    // Removed old typewriter logic as the new UI relies on sleek static rendering.

    // Smooth Scrolling for Navigation Links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            const href = this.getAttribute('href');
            if (href !== '#') {
                e.preventDefault();
                const target = document.querySelector(href);
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            }
        });
    });

    // --------------------------------------------------------
    // Three.js 3D Interactive Cyber Network
    // --------------------------------------------------------
    if (typeof THREE !== 'undefined') {
        const canvas = document.getElementById('webgl-canvas');

        // Scene setup
        const scene = new THREE.Scene();
        // Fog for depth
        scene.fog = new THREE.FogExp2(0x030305, 0.001);

        const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 2000);
        camera.position.z = 400;

        const renderer = new THREE.WebGLRenderer({ canvas: canvas, alpha: true, antialias: true });
        renderer.setSize(window.innerWidth, window.innerHeight);
        renderer.setPixelRatio(window.devicePixelRatio);

        // Geometry: Nodes
        const particleCount = 1000;
        const geometry = new THREE.BufferGeometry();
        const positions = new Float32Array(particleCount * 3);
        const colors = new Float32Array(particleCount * 3);

        const colorPalette = [
            new THREE.Color(0x818cf8), // Primary Accent
            new THREE.Color(0xc084fc), // Secondary Accent
            new THREE.Color(0x38bdf8)  // Tertiary Accent
        ];

        for (let i = 0; i < particleCount; i++) {
            // Spherical distribution
            const theta = Math.random() * Math.PI * 2;
            const phi = Math.acos((Math.random() * 2) - 1);
            const radius = 200 + Math.random() * 200;

            positions[i * 3] = radius * Math.sin(phi) * Math.cos(theta);
            positions[i * 3 + 1] = radius * Math.sin(phi) * Math.sin(theta);
            positions[i * 3 + 2] = radius * Math.cos(phi);

            // Assign random color from palette
            const color = colorPalette[Math.floor(Math.random() * colorPalette.length)];
            colors[i * 3] = color.r;
            colors[i * 3 + 1] = color.g;
            colors[i * 3 + 2] = color.b;
        }

        geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

        // Material for Nodes
        const material = new THREE.PointsMaterial({
            size: 3,
            vertexColors: true,
            transparent: true,
            opacity: 0.8,
            sizeAttenuation: true
        });

        const particleSystem = new THREE.Points(geometry, material);
        scene.add(particleSystem);

        // Lines (Connections)
        const lineMaterial = new THREE.LineBasicMaterial({
            color: 0x818cf8,
            transparent: true,
            opacity: 0.1
        });

        // Connect some close particles
        const lineGeometry = new THREE.BufferGeometry();
        const linePositions = [];

        // For performance, only connect a subset
        const connectCount = 200;
        for(let i=0; i<connectCount; i++) {
            const p1 = new THREE.Vector3(positions[i*3], positions[i*3+1], positions[i*3+2]);
            for(let j=i+1; j<connectCount; j++) {
                const p2 = new THREE.Vector3(positions[j*3], positions[j*3+1], positions[j*3+2]);
                if(p1.distanceTo(p2) < 80) {
                    linePositions.push(p1.x, p1.y, p1.z);
                    linePositions.push(p2.x, p2.y, p2.z);
                }
            }
        }

        lineGeometry.setAttribute('position', new THREE.Float32BufferAttribute(linePositions, 3));
        const lines = new THREE.LineSegments(lineGeometry, lineMaterial);
        scene.add(lines);

        // Group to rotate together
        const networkGroup = new THREE.Group();
        networkGroup.add(particleSystem);
        networkGroup.add(lines);
        scene.add(networkGroup);

        // Interaction state
        let mouseX = 0;
        let mouseY = 0;
        let targetX = 0;
        let targetY = 0;
        const windowHalfX = window.innerWidth / 2;
        const windowHalfY = window.innerHeight / 2;

        document.addEventListener('mousemove', (event) => {
            mouseX = (event.clientX - windowHalfX) * 0.5;
            mouseY = (event.clientY - windowHalfY) * 0.5;
        });

        // Animation Loop
        function animate() {
            requestAnimationFrame(animate);

            // Smooth interpolation towards mouse position
            targetX = mouseX * 0.001;
            targetY = mouseY * 0.001;

            networkGroup.rotation.y += 0.05 * (targetX - networkGroup.rotation.y);
            networkGroup.rotation.x += 0.05 * (targetY - networkGroup.rotation.x);

            // Constant base rotation
            networkGroup.rotation.y += 0.001;
            networkGroup.rotation.z += 0.0005;

            renderer.render(scene, camera);
        }

        animate();

        // Handle Resize
        window.addEventListener('resize', () => {
            camera.aspect = window.innerWidth / window.innerHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(window.innerWidth, window.innerHeight);
        });
    } else {
        console.warn("Three.js not loaded.");
    }
});
