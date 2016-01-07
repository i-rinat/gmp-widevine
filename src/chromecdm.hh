#pragma once

#include <stdlib.h>
#include <crcdm/content_decryption_module.h>
#include <gmp/gmp-decryption.h>


namespace crcdm {

void
Initialize();

void
Deinitialize();

cdm::ContentDecryptionModule *
get();

void
set_create_session_token(uint32_t create_session_token);


} // namespace crcdm
