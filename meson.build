project(
	'laf',
	'c'
)
# TODO: Fix build fail from flag:
#	'-fsanitize=address,undefined,leak', # undefined access
#	'-O2', # unused results.
add_project_arguments([
	'-D_FORTIFY_SOURCE=2', 
	'-fasynchronous-unwind-tables',
	'-fexceptions',
	'-fpie',
	'-fpic',
	'-fsanitize=address,undefined,leak',
	'-O2', 
	'-pipe',
	'-pedantic',
	'-Wall',
	'-Wextra',
	'-Werror',
	'-Werror=format',
	'-Werror=format-security',
	'-Werror=array-bounds',
	'-Werror=implicit-function-declaration',
	'-g',
	'-Wformat',
	'-Wformat-security'],
	language:	'c')

nfq = dependency('libnetfilter_queue')

src = ['main.c', 'procs.c']

executable('laf', src, dependencies : nfq)
