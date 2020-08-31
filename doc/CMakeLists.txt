configure_file(Doxyfile.in Doxyfile)
add_custom_target(doc COMMAND ${DOXYGEN_EXECUTABLE})
