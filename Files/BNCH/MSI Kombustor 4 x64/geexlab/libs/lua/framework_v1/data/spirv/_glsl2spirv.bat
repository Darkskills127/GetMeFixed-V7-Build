rem glslangValidator_x32 -h > help.txt

glslangValidator 03-vs.vert -V -o 03-vs.spv
glslangValidator 03-ps.frag -V -o 03-ps.spv

glslangValidator 06-vs.vert -V -o 06-vs.spv
glslangValidator 06-ps.frag -V -o 06-ps.spv

pause