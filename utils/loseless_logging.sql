-- 1. Accendi i terminali nell'area di interesse
UPDATE basic_blocks
SET to_trace = 1
WHERE file_path LIKE '%BusinessLogic%'
    AND reason IN (
        'Proof of Completion (Final Exit Block)',
        'Early Exit (Guard Clause/Jump)',
        'Early Exit (Guard Clause/Jump - CFG Fallback)',
        'Exception Handler (Catch)'
    );
-- 2. Accendi i blocchi foglia (nessun blocco è strettamente contenuto in essi)
WITH Leaves AS (
    SELECT b1.id
    FROM basic_blocks b1
    WHERE b1.file_path LIKE '%BusinessLogic%'
        AND NOT EXISTS (
            SELECT 1
            FROM basic_blocks b2
            WHERE b2.method_signature = b1.method_signature
                AND b2.file_path = b1.file_path
                AND b2.id != b1.id -- B2 è contenuto dentro B1
                AND b2.block_start_line >= b1.block_start_line
                AND b2.block_end_line <= b1.block_end_line -- Disambiguazione per duplicati perfetti
                AND (
                    b2.block_start_line > b1.block_start_line
                    OR b2.block_end_line < b1.block_end_line
                    OR b2.id > b1.id
                )
        )
)
UPDATE basic_blocks
SET to_trace = 1
WHERE id IN (
        SELECT id
        FROM Leaves
    );