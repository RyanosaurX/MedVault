
;; MedVault - Secure Medical Records Contract
;; A secure system for storing and sharing medical records with proper authorization

;; Define data variables
(define-data-var admin principal tx-sender)

(define-map patient-records 
  { patient-id: (string-ascii 20) }
  { 
    owner: principal,
    encrypted-data-hash: (buff 32),
    last-updated: uint,
    record-version: uint
  }
)

(define-map authorized-viewers
  { 
    patient-id: (string-ascii 20),
    viewer: principal
  }
  {
    can-view: bool,
    can-edit: bool,
    expires-at: uint
  }
)

(define-map access-log
  {
    patient-id: (string-ascii 20),
    timestamp: uint
  }
  {
    accessor: principal,
    access-type: (string-ascii 10)
  }
)

;; Error codes
(define-constant ERR-NOT-AUTHORIZED u100)
(define-constant ERR-ALREADY-EXISTS u101)
(define-constant ERR-DOES-NOT-EXIST u102)
(define-constant ERR-EXPIRED-ACCESS u103)
(define-constant ERR-INVALID-INPUT u104)

;; Check if caller is admin
(define-private (is-admin)
  (is-eq tx-sender (var-get admin))
)

;; Validate patient ID format
(define-private (is-valid-patient-id (patient-id (string-ascii 20)))
  (>= (len patient-id) u1)
)

;; Validate data hash
(define-private (is-valid-hash (data-hash (buff 32)))
  (is-eq (len data-hash) u32)
)

;; Validate viewer principal
(define-private (is-valid-viewer (viewer principal))
  (not (is-eq viewer tx-sender))
)

;; Check if caller is record owner
(define-private (is-owner (patient-id (string-ascii 20)))
  (let ((record (map-get? patient-records { patient-id: patient-id })))
    (if (is-some record)
      (is-eq tx-sender (get owner (unwrap! record false)))
      false
    )
  )
)

;; Check if caller has appropriate access
(define-private (has-access (patient-id (string-ascii 20)) (require-edit bool))
  (let (
    (access-info (map-get? authorized-viewers { patient-id: patient-id, viewer: tx-sender }))
    (current-time (get-block-info? time u0))
  )
    (if (is-some access-info)
      (if (is-some current-time)
        (let ((unwrapped-access (unwrap-panic access-info))
             (unwrapped-time (unwrap-panic current-time)))
          (and
            (< unwrapped-time (get expires-at unwrapped-access))
            (if require-edit
              (get can-edit unwrapped-access)
              (get can-view unwrapped-access)
            )
          )
        )
        false
      )
      false
    )
  )
)

;; Log access to medical records
(define-private (log-access (patient-id (string-ascii 20)) (access-type (string-ascii 10)))
  (let ((current-time (get-block-info? time u0)))
    (if (is-some current-time)
      (begin
        (map-set access-log
          { patient-id: patient-id, timestamp: (unwrap-panic current-time) }
          { accessor: tx-sender, access-type: access-type }
        )
        true
      )
      false
    )
  )
)

;; Add a new medical record
(define-public (add-record (patient-id (string-ascii 20)) (data-hash (buff 32)))
  (begin
    (asserts! (is-valid-patient-id patient-id) (err ERR-INVALID-INPUT))
    (asserts! (is-valid-hash data-hash) (err ERR-INVALID-INPUT))
    (match (get-block-info? time u0)
      current-time (begin
        (asserts! (is-none (map-get? patient-records { patient-id: patient-id })) (err ERR-ALREADY-EXISTS))
        (map-set patient-records
          { patient-id: patient-id }
          { 
            owner: tx-sender,
            encrypted-data-hash: data-hash,
            last-updated: current-time,
            record-version: u1
          }
        )
        (map-set access-log
          { patient-id: patient-id, timestamp: current-time }
          { accessor: tx-sender, access-type: "create" }
        )
        (ok true))
      (err ERR-NOT-AUTHORIZED))
  )
)

;; Update an existing medical record
(define-public (update-record (patient-id (string-ascii 20)) (data-hash (buff 32)))
  (begin
    (asserts! (is-valid-patient-id patient-id) (err ERR-INVALID-INPUT))
    (asserts! (is-valid-hash data-hash) (err ERR-INVALID-INPUT))
    (match (get-block-info? time u0)
      current-time (match (map-get? patient-records { patient-id: patient-id })
        record-data (begin
          (asserts! (or (is-owner patient-id) (has-access patient-id true)) (err ERR-NOT-AUTHORIZED))
          (map-set patient-records
            { patient-id: patient-id }
            { 
              owner: (get owner record-data),
              encrypted-data-hash: data-hash,
              last-updated: current-time,
              record-version: (+ u1 (get record-version record-data))
            }
          )
          (map-set access-log
            { patient-id: patient-id, timestamp: current-time }
            { accessor: tx-sender, access-type: "update" }
          )
          (ok true))
        (err ERR-DOES-NOT-EXIST))
      (err ERR-NOT-AUTHORIZED))
  )
)

;; Grant access to a medical professional or other authorized party
(define-public (grant-access 
  (patient-id (string-ascii 20)) 
  (viewer principal) 
  (can-edit bool) 
  (duration uint)
)
  (begin
    (asserts! (is-valid-patient-id patient-id) (err ERR-INVALID-INPUT))
    (asserts! (is-valid-viewer viewer) (err ERR-INVALID-INPUT))
    (asserts! (> duration u0) (err ERR-INVALID-INPUT))
    (match (get-block-info? time u0)
      current-time (begin
        (asserts! (is-owner patient-id) (err ERR-NOT-AUTHORIZED))
        (map-set authorized-viewers
          { patient-id: patient-id, viewer: viewer }
          { 
            can-view: true,
            can-edit: can-edit,
            expires-at: (+ current-time duration)
          }
        )
        (map-set access-log
          { patient-id: patient-id, timestamp: current-time }
          { accessor: tx-sender, access-type: "grant" }
        )
        (ok true))
      (err ERR-NOT-AUTHORIZED))
  )
)

;; Revoke access previously granted
(define-public (revoke-access (patient-id (string-ascii 20)) (viewer principal))
  (begin
    (asserts! (is-valid-patient-id patient-id) (err ERR-INVALID-INPUT))
    (asserts! (is-valid-viewer viewer) (err ERR-INVALID-INPUT))
    (match (get-block-info? time u0)
      current-time (begin
        (asserts! (is-owner patient-id) (err ERR-NOT-AUTHORIZED))
        (map-delete authorized-viewers { patient-id: patient-id, viewer: viewer })
        (map-set access-log
          { patient-id: patient-id, timestamp: current-time }
          { accessor: tx-sender, access-type: "revoke" }
        )
        (ok true))
      (err ERR-NOT-AUTHORIZED))
  )
)

;; Get record details - only available to owner or authorized viewers
(define-read-only (get-record (patient-id (string-ascii 20)))
  (begin
    (asserts! (is-valid-patient-id patient-id) (err ERR-INVALID-INPUT))
    (match (get-block-info? time u0)
      current-time (match (map-get? patient-records { patient-id: patient-id })
        record-data (begin
          (asserts! (or (is-owner patient-id) (has-access patient-id false)) (err ERR-NOT-AUTHORIZED))
          (ok record-data))
        (err ERR-DOES-NOT-EXIST))
      (err ERR-NOT-AUTHORIZED))
  )
)

;; Check if a viewer has current access to a record
(define-read-only (check-access (patient-id (string-ascii 20)) (viewer principal))
  (begin
    (asserts! (is-valid-patient-id patient-id) (err ERR-INVALID-INPUT))
    (asserts! (is-valid-viewer viewer) (err ERR-INVALID-INPUT))
    (match (get-block-info? time u0)
      current-time (match (map-get? authorized-viewers { patient-id: patient-id, viewer: viewer })
        access (if (< current-time (get expires-at access))
          (ok { 
            has-access: true, 
            can-edit: (get can-edit access), 
            time-remaining: (- (get expires-at access) current-time) 
          })
          (ok { has-access: false, can-edit: false, time-remaining: u0 }))
        (ok { has-access: false, can-edit: false, time-remaining: u0 }))
      (err ERR-NOT-AUTHORIZED))
  )
)

;; Transfer ownership of a medical record
(define-public (transfer-ownership (patient-id (string-ascii 20)) (new-owner principal))
  (begin
    (asserts! (is-valid-patient-id patient-id) (err ERR-INVALID-INPUT))
    (asserts! (is-valid-viewer new-owner) (err ERR-INVALID-INPUT))
    (match (get-block-info? time u0)
      current-time (match (map-get? patient-records { patient-id: patient-id })
        record-data (begin
          (asserts! (is-owner patient-id) (err ERR-NOT-AUTHORIZED))
          (map-set patient-records
            { patient-id: patient-id }
            { 
              owner: new-owner,
              encrypted-data-hash: (get encrypted-data-hash record-data),
              last-updated: current-time,
              record-version: (get record-version record-data)
            }
          )
          (map-set access-log
            { patient-id: patient-id, timestamp: current-time }
            { accessor: tx-sender, access-type: "transfer" }
          )
          (ok true))
        (err ERR-DOES-NOT-EXIST))
      (err ERR-NOT-AUTHORIZED))
  )
)

;; Change admin (only available to current admin)
(define-public (change-admin (new-admin principal))
  (begin
    (asserts! (is-admin) (err ERR-NOT-AUTHORIZED))
    (asserts! (is-valid-viewer new-admin) (err ERR-INVALID-INPUT))
    (ok (var-set admin new-admin))
  )
)