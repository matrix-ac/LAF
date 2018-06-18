project(
	'laf',
	'c'
)
# TODO: Fix build fail from flag -fsanitize=address,undefined. 
add_project_arguments(['-fsanitize=address,undefined', '-pedantic', '-Wall', '-Wextra', '-Werror', '-Werror=format', '-Werror=format-security', '-Werror=array-bounds', '-g', '-Wformat', '-Wformat-security'], language: 'c')

nfq = dependency('libnetfilter_queue')

src = ['main.c', 'procs.c']

executable('laf', src, dependencies : nfq)
