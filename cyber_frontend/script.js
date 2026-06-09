document.addEventListener('DOMContentLoaded', () => {
    // Typewriter Effect
    const texts = [
        "Initializing secure connection...",
        "Bypassing mainframe firewalls...",
        "Access granted. Welcome to LHR_CYBER.",
        "Learn to defend. Learn to attack.",
        "Master the matrix."
    ];
    let count = 0;
    let index = 0;
    let currentText = '';
    let letter = '';
    const typewriterElement = document.getElementById('typewriter');

    function type() {
        if (count === texts.length) {
            count = 0;
        }
        currentText = texts[count];
        letter = currentText.slice(0, ++index);

        if (typewriterElement) {
            typewriterElement.textContent = letter + '█';
        }

        if (letter.length === currentText.length) {
            setTimeout(() => {
                index = 0;
                count++;
                type();
            }, 2000);
        } else {
            setTimeout(type, 100);
        }
    }

    if (typewriterElement) {
        type();
    }

    // Smooth Scrolling for Navigation Links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });

    // Terminal Form Submission Simulation
    const contactForm = document.getElementById('contact-form');
    const terminalResponse = document.getElementById('terminal-response');

    if (contactForm) {
        contactForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const btn = contactForm.querySelector('button');
            const originalText = btn.textContent;

            btn.textContent = 'Processing...';
            btn.disabled = true;

            // Simulate network request
            setTimeout(() => {
                contactForm.style.display = 'none';
                if (terminalResponse) {
                    terminalResponse.classList.remove('hidden');
                }
            }, 1500);
        });
    }

    // Terminal Window Controls (Visual only)
    document.querySelectorAll('.terminal-buttons span').forEach(btn => {
        btn.addEventListener('click', () => {
            if (btn.classList.contains('close')) {
                const termBody = document.querySelector('.terminal-body');
                if (termBody) {
                    termBody.innerHTML = '<p class="prompt" style="color:red">> Connection Terminated.</p>';
                }
            }
        });
    });

    // Particles.js Initialization
    if (window.particlesJS) {
        particlesJS('particles-js', {
            "particles": {
                "number": {
                    "value": 80,
                    "density": {
                        "enable": true,
                        "value_area": 800
                    }
                },
                "color": {
                    "value": "#00ffcc"
                },
                "shape": {
                    "type": "circle",
                    "stroke": {
                        "width": 0,
                        "color": "#000000"
                    },
                    "polygon": {
                        "nb_sides": 5
                    }
                },
                "opacity": {
                    "value": 0.5,
                    "random": false,
                    "anim": {
                        "enable": false,
                        "speed": 1,
                        "opacity_min": 0.1,
                        "sync": false
                    }
                },
                "size": {
                    "value": 3,
                    "random": true,
                    "anim": {
                        "enable": false,
                        "speed": 40,
                        "size_min": 0.1,
                        "sync": false
                    }
                },
                "line_linked": {
                    "enable": true,
                    "distance": 150,
                    "color": "#00ffcc",
                    "opacity": 0.4,
                    "width": 1
                },
                "move": {
                    "enable": true,
                    "speed": 2,
                    "direction": "none",
                    "random": false,
                    "straight": false,
                    "out_mode": "out",
                    "bounce": false,
                    "attract": {
                        "enable": false,
                        "rotateX": 600,
                        "rotateY": 1200
                    }
                }
            },
            "interactivity": {
                "detect_on": "canvas",
                "events": {
                    "onhover": {
                        "enable": true,
                        "mode": "grab"
                    },
                    "onclick": {
                        "enable": true,
                        "mode": "push"
                    },
                    "resize": true
                },
                "modes": {
                    "grab": {
                        "distance": 140,
                        "line_linked": {
                            "opacity": 1
                        }
                    },
                    "bubble": {
                        "distance": 400,
                        "size": 40,
                        "duration": 2,
                        "opacity": 8,
                        "speed": 3
                    },
                    "repulse": {
                        "distance": 200,
                        "duration": 0.4
                    },
                    "push": {
                        "particles_nb": 4
                    },
                    "remove": {
                        "particles_nb": 2
                    }
                }
            },
            "retina_detect": true
        });
    }
});
