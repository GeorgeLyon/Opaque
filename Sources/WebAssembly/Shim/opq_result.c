#import "libopaque.h"

OPQResultType opq_result_type_success() {
    return OPQ_SUCCESS;
}

OPQResultType opq_result_type_failure() {
    return OPQ_FAILURE;
}

OPQResultType opq_result_type_fatal_error() {
    return OPQ_FATAL_ERROR;
}

OPQResultType opq_result_type(const opq_result *result) {
    return result->type;
}

/// Only valid if result->type is not "success"
const char *opq_result_message(const opq_result *result) {
    return result->body.failure.message;
}
