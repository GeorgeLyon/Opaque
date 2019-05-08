import CLibOpaque

extension opq_result.__Unnamed_union_body.__Unnamed_struct_failure: Error {
    
}

extension opq_result {
    
    func throwIfError() throws {
        switch type {
        case OPQ_SUCCESS:
            break
        case OPQ_FAILURE:
            throw body.failure
        default:
            fatalError(String(cString: body.failure.message))
        }
    }
    
}
