from setuptools import setup, find_packages

setup(
    name="ssol",
    version="1.0.0",
    description="SecureShield OS Layer (SSOL) - Advanced AI-Powered Sovereign OS Security Framework",
    author="SSOL Security Engineering Operations",
    packages=find_packages(),
    py_modules=[
        "ssol_daemon",
        "ssol_dns_security",
        "ssol_threat_intel",
        "ssol_ueba_engine",
        "ssol_supply_chain_guard",
        "ssol_zero_trust",
        "ssol_privilege_manager",
        "ssol_microsandbox",
        "ssol_memory_forensics",
        "ssol_pre_install_check",
        "ssol_behavioral_monitor",
        "ssol_deception_trap",
        "ssol_forensics_grc",
        "ssol_sovereign_shield",
        "ssol_exec_probe",
        "ssol_feature_extractor",
        "ssol_fp_reducer",
        "ssol_gnn_lateral",
        "ssol_lstm_hardened",
        "ssol_tier3_hardened"
    ],
    install_requires=[
        "PyYAML>=6.0.1",
        "PyJWT>=2.8.0",
        "Flask>=3.0.2",
        "scapy>=2.5.0",
        "taxii2client>=2.1.0",
        "mitreattack-python>=2.0.0"
    ],
    entry_points={
        "console_scripts": [
            "ssol-daemon=ssol_daemon:start_daemon"
        ]
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: System Administrators",
        "License :: Other/Proprietary License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security"
    ]
)
