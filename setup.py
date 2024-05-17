from setuptools import setup, find_packages

setup(
    name="loginllama",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "requests",
    ],
    author="Josh Ghent",
    author_email="me@joshghent.com",
    description="LoginLlama Python SDK for detecting suspicious logins",
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url="https://github.com/joshghent/loginllama.py",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
