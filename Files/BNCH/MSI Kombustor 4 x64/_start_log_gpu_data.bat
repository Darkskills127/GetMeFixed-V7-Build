@echo off

echo MSI Kombustor 2019
echo --------------------

rem Syntax

rem MSI-Kombustor-x64.exe -log_gpu_data -append_date_to_gpu_log_file -nogui -width=<xxxx> -height=<xxxx> -<test_name> -fullscreen -gpu_index=<x>

rem -log_gpu_data     : enables GPU data logging.
rem -append_date_to_gpu_log_file: append the current date to the gpu data log filename.
rem -nogui            : disables main user interface. Starts the test directly.
rem -width=<xxx>      : sets the test width.
rem -height=<xxx>     : sets the test height.
rem -fullscreen       : fullscreen mode
rem -gpu_index=<x>    : GPU index (Vulkan only) : 0 (first GPU), 1 (second GPU), 2 (third GPU), 3 ...

rem -<test_name>      :
rem "vkfurrytorus"
rem "glfurrytorus"
rem "vkfurrymsi"
rem "glfurrymsi"

rem "glfurmark1700mb"
rem "glfurmark3200mb"
rem "glfurmark5200mb"
rem "glfurmark6500mb"

rem "glmsi01burn"
rem "glmsi01"

rem "glphongdonut"
rem "vkphongdonut"

rem "glpbrdonut"

rem "vktessyspherex32"
rem "vktessyspherex16"
rem "gltessyspherex32"
rem "gltessyspherex16"


rem --------------------------------------------------------------------------
MSI-Kombustor-x64.exe -log_gpu_data -append_date_to_gpu_log_file -nogui -width=1920 -height=1080 -glfurrymsi
rem --------------------------------------------------------------------------

