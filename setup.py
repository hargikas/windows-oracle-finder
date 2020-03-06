import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="windows-oracle-finder", 
    version="0.2.1",
    author="Charalampos Gkikas",
    author_email="hargikas@gmail.com",
    description="A small package for windows machines to find where the installation of oracle client resides.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/hargikas/windows-oracle-finder",
    packages=setuptools.find_packages(),
    license='MIT',
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        "Programming Language :: Python :: 3",

        # Pick your license as you wish (should match "license" above)
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
    ],
    python_requires='>=3',
    install_requires=['pefile', 'logzero', 'pywin32'],
    keywords='oracle windows client instantclient',
    project_urls={
        #'Documentation': 'https://packaging.python.org/tutorials/distributing-packages/',
        #'Funding': 'https://donate.pypi.org',
        #'Say Thanks!': 'http://saythanks.io/to/example',
        'Source': 'https://github.com/hargikas/windows-oracle-finder/',
        'Tracker': 'https://github.com/hargikas/windows-oracle-finder/issues',
    },
    entry_points={
    'console_scripts': [
        'find_oracle=find_oracle:__main__',
    ],
},
)