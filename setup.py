try:
    from setuptools import setup
except ImportError:
    # can't have the entry_points option here.
    from distutils.core import setup

setup(name='flask_itsyouonline',
      version='1.3.6',
      author="Ahmed T. Youssef",
      author_email="xmonader@gmail.com",
      description='Itsyou.online middleware for Flask.',
      long_description='Itsyou.online middleware for Flask.',
      py_modules=['flask_itsyouonline'],
      url="http://github.com/xmonader/flask_itsyouonline",
      license='BSD 3-Clause License',
      install_requires=['requests', 'pyjwt'],
      classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved',
        'License :: OSI Approved :: BSD License',
        'Operating System :: MacOS',
        'Operating System :: POSIX',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules',
      ],
      )
