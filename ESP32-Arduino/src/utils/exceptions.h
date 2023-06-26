#ifndef EXCEPTION_H
#define EXCEPTION_H

#include <stdexcept>

#define CATCH_CUSTOM_ERRORS_AND_RETURN_SW                                                          \
    catch (const FileError& error)                                                                 \
    {                                                                                              \
        debugMsg("[E] FileError:" + String(error.what()));                                         \
        log_error((String("FileError: ") + String(error.what())).c_str());                         \
        return SW_FILE_ERROR;                                                                      \
    }                                                                                              \
    catch (const SecurityError& error)                                                             \
    {                                                                                              \
        debugMsg("[E] SecurityError:" + String(error.what()));                                     \
        log_error((String("SecurityError: ") + String(error.what())).c_str());                     \
        return SW_SECURITY_STATUS_NOT_SATISFIED;                                                   \
    }                                                                                              \
    catch (const WrongLeError& error)                                                              \
    {                                                                                              \
        debugMsg("[E] WrongLeError:" + String(error.what()));                                      \
        log_error((String("WrongLeError: ") + String(error.what())).c_str());                      \
        return SW_WRONG_LENGTH_EXPECTED;                                                           \
    }                                                                                              \
    catch (const CustomError& error)                                                               \
    {                                                                                              \
        debugMsg("[E] CustomError:" + String(error.what()));                                       \
        log_error((String("CustomError: ") + String(error.what())).c_str());                       \
        return SW_INTERNAL_ERROR;                                                                  \
    }                                                                                              \
    catch (const std::exception& error)                                                            \
    {                                                                                              \
        debugMsg("[E] std::exception:" + String(error.what()));                                    \
        log_error((String("std::exception: ") + String(error.what())).c_str());                    \
        return SW_INTERNAL_ERROR;                                                                  \
    }                                                                                              \
    catch (...)                                                                                    \
    {                                                                                              \
        debugMsg("[E] Unknown error");                                                             \
        log_error("Unknown error");                                                                \
        return SW_INTERNAL_ERROR;                                                                  \
    }

class CustomError : public std::runtime_error
{
protected:
    using std::runtime_error::runtime_error;
};

class WrongLeError : public CustomError
{
    using CustomError::CustomError;
};

class FileError : public CustomError
{
    using CustomError::CustomError;
};

class SecurityError : public CustomError
{
    using CustomError::CustomError;
};

#endif