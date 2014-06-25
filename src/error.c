#include "error.h"
#include "utils.h"

const char * errmsg[] = {
    "Nothing goes wrong, really.", // Not an error
    "Error connect to DB",         // Fail to connect to db
    "Where's the key?",            // No key
    "User defined privacy_user_{algo}.so not found",   // user lib
    "User defined {algo}_dec or {algo}_enc not found", // user function
    "Try to compress non-numstring",                   // non-numstring
    "What I supposed to to with a null colid?",        // NULL colid
    "Config file not found",                           // config file not found
    "Executable pputil not found",    // DBUTILS
    "INDEED A BUG! Wrong params passd to pputil", // cli param error
    "Running pputil in an shell",
    "MD5 check on user lib fail", // MD5 check fail
    "DEBUG BREAKPOINT",           // FOR DEBUG USE ONLY
    "Column no longer encryptred",      // not encrypt
    "Updating, try later"        ,      // Updating
    "Fail to update column status",     // updating status fail
    "No more memory",                   // NO Memory
    "Already encrypted",                // Alreay encrypted
    "Insert db failed",                // Insert db failed
};
