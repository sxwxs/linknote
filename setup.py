from setuptools import setup, find_packages

setup(
    name="linknote",
    version="0.1.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'flask>=2.0.0',
        'click>=7.0',
        'PyYAML>=6.0',
        'qrcode>=7.0',
    ],
    entry_points={
        'console_scripts': [
            'linknote=linknote.cli:main',
        ],
    },
    package_data={
        'linknote': [
            'static/index.html',
            'static/style.css',
            'static/script.js',
            'static/data.js'
        ],
    },
    python_requires='>=3.7',
    author="Your Name",
    description="A web-based bookmark manager with search and tagging capabilities",
    keywords="bookmarks, notes, web",
)
