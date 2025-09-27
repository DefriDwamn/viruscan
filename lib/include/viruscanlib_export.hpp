#pragma once

#ifdef _WIN32
    #ifdef VIRUSCANLIB_EXPORTS
        #define VIRUSCANLIB_API __declspec(dllexport)
    #else
        #define VIRUSCANLIB_API __declspec(dllimport)
    #endif
#else
    #define VIRUSCANLIB_API
#endif