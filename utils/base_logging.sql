-- 1. Resetta tutto a zero
UPDATE basic_blocks
SET to_trace = 0;
-- 2. Accendi tutti i terminali
UPDATE basic_blocks
SET to_trace = 1
WHERE reason IN (
        'Proof of Completion (Final Exit Block)',
        'Early Exit (Guard Clause/Jump)',
        'Early Exit (Guard Clause/Jump - CFG Fallback)',
        'Exception Handler (Catch)'
    );