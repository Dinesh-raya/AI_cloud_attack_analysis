from setuptools import setup, find_packages

setup(
    name="cloud_attack_analysis",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "python-hcl2==4.3.5",
        "networkx==3.2.1",
        "colorama==0.4.6"
    ],
    entry_points={
        'console_scripts': [
            'cloud-attack-analysis=cloud_attack_analysis.cli:main',
        ],
    },
)
