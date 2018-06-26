project(clienttests C)

find_package(socket_wrapper)

set(LIBSSH_CLIENT_TESTS
    torture_algorithms
    torture_connect
    torture_auth
    torture_forward
    torture_knownhosts
    torture_knownhosts_verify
    torture_proxycommand
    torture_session
    torture_request_env)

if (WITH_SFTP)
    set(LIBSSH_CLIENT_TESTS
        ${LIBSSH_CLIENT_TESTS}
        torture_sftp_ext
        torture_sftp_dir
        torture_sftp_read
        torture_sftp_fsync)
endif (WITH_SFTP)

foreach(_CLI_TEST ${LIBSSH_CLIENT_TESTS})
    add_cmocka_test(${_CLI_TEST} ${_CLI_TEST}.c ${TORTURE_LIBRARY})

    if (OSX)
        set_property(
            TEST
                ${_CLI_TEST}
            PROPERTY
            ENVIRONMENT DYLD_FORCE_FLAT_NAMESPACE=1;DYLD_INSERT_LIBRARIES=${SOCKET_WRAPPER_LIBRARY})
    else ()
        set_property(
            TEST
                ${_CLI_TEST}
            PROPERTY
                ENVIRONMENT ${TORTURE_ENVIRONMENT})
    endif()
endforeach()
