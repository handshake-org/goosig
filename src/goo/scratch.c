
int
goo_verify(
  goo_group_t *group,

  // pubkey
  const unsigned char *C1,
  size_t C1_len,
  const unsigned char *C2,
  size_t C2_len,
  const unsigned char *t,
  size_t t_len,

  // msg
  const unsigned char *msg,
  size_t msg_len,

  // sigma
  const unsigned char *chall,
  size_t chall_len,
  const unsigned char *ell,
  size_t ell_len,
  const unsigned char *Aq,
  size_t Aq_len,
  const unsigned char *Bq,
  size_t Bq_len,
  const unsigned char *Cq,
  size_t Cq_len,
  const unsigned char *Dq,
  size_t Dq_len,

  // z_prime
  const unsigned char *zp_w,
  size_t zp_w_len,
  const unsigned char *zp_w2,
  size_t zp_w2_len,
  const unsigned char *zp_s1,
  size_t zp_s1_len,
  const unsigned char *zp_a,
  size_t zp_a_len,
  const unsigned char *zp_an,
  size_t zp_an_len,
  const unsigned char *zp_s1w,
  size_t zp_s1w_len,
  const unsigned char *zp_sa
  size_t zp_sa_len
) {
  goo_import(group->C1, C1, C1_len);
  goo_import(group->C2, C2, C2_len);
  goo_import(group->t, t, t_len);

  goo_import(group->msg, msg, msg_len);

  goo_import(group->chall, chall, chall_len);
  goo_import(group->ell, ell, ell_len);
  goo_import(group->Aq, Aq, Aq_len);
  goo_import(group->Bq, Bq, Bq_len);
  goo_import(group->Cq, Cq, Cq_len);
  goo_import(group->Dq, Dq, Dq_len);

  goo_import(group->zp_w, zp_w, zp_w_len);
  goo_import(group->zp_w2, zp_w2, zp_w2_len);
  goo_import(group->zp_s1, zp_s1, zp_s1_len);
  goo_import(group->zp_a, zp_a, zp_a_len);
  goo_import(group->zp_an, zp_an, zp_an_len);
  goo_import(group->zp_s1w, zp_s1w, zp_s1w_len);
  goo_import(group->zp_sa, zp_sa, zp_sa_len);

  return goo_group_verify(
    group,

    // pubkey
    group->C1,
    group->C2,
    group->t,

    // msg
    group->msg,

    // sigma
    group->chall,
    group->ell,
    group->Aq,
    group->Bq,
    group->Cq,
    group->Dq,

    // z_prime
    group->zp_w,
    group->zp_w2,
    group->zp_s1,
    group->zp_a,
    group->zp_an,
    group->zp_s1w,
    group->zp_sa
  );
}

