import hashlib
import hmac
import json

calculated_hmac = hmac.new(b'qweerthyhj23rwefrgfdbnhjnm32rwefdsgvbghmu',
                           b'{"username":"smallaccount","user_id":1844,"avatar":"/letter_avatar_proxy/v4/letter/s/f19dbf/{size}.png","group":null}',
                           hashlib.sha256).hexdigest()

calculated_hmac2 = hmac.new(bytes('qweerthyhj23rwefrgfdbnhjnm32rwefdsgvbghmu', 'utf-8'),

                            bytes(
                                '{"username":"smallaccount","user_id":1844,"avatar":"/letter_avatar_proxy/v4/letter/s/f19dbf/{size}.png","group":null}',
                                'utf-8'),
                            hashlib.sha256).hexdigest()
print()
