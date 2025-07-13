from setuptools import setup, find_packages

with open('README.md', encoding='utf-8') as f:
    long_description = f.read()

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
        'captcha>=0.6.0',
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
    author="sxwxs",
    description="A web-based short note manager with search and tagging capabilities",
    license="MIT",
    keywords="bookmarks, notes, web application, tagging, search, flask",
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/sxwxs/linknote',
    project_urls={
        'Bug Reports': 'https://github.com/sxwxs/linknote/issues',
        'Source Code': 'https://github.com/sxwxs/linknote',
    },
        classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
    ],
)
