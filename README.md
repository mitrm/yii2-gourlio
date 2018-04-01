gourl.io
========
Прием платежей в биткоинах и альткойнах

Installation
------------

The preferred way to install this extension is through [composer](http://getcomposer.org/download/).

Either run

```
composer require --prefer-dist gourlio/yii2-gourlio "*"
```

or add

```
"gourlio/yii2-gourlio": "*"
```

to the require section of your `composer.json` file.


Usage
-----

В config/main.php добавить

```php
'components' => [
    'gourlio' => [
        'class' => 'mitrm\gourlio\Cryptobox',
        'period' => 'NOEXPIRY',
        'all_key' => [
            'bitcoin' => ['public_key' => '', 'private_key' => ''],
            'speedcoin' => ['public_key' => '', 'private_key' => ''],
            ...
        ]
    ],
]
```

Формирование данных для оплаты
```php
$options = array(
    'order_id' => $order_id,
    'user_id' => Yii::$app->user->id,
    'amount' => $sum,
    'coinName' => 'speedcoin', // bitcoin ...
);
$data_pay = Yii::$app->gourlio->load($options)->getPaymentData();

$data_pay['addr']; // Номер кошелька для перевода средств
$data_pay['amount']; // сумма к оплате
```

Проверка оплаты
```php
$options = array(
    'order_id' => $order_id,
    'user_id' => Yii::$app->user->id,
    'amount' => $sum,
    'coinName' => 'speedcoin', // bitcoin ...
);
if(Yii::$app->gourlio->load($options)->isPaid())  {
    // Оплата пришла
}
```

Получение оповещений по оплате от gourl.io

```php
class PaymentsController extends Controller
{
    public $enableCsrfValidation = false;

    /**
     * @inheritdoc
     */
    public function actions()
    {
        return [
            'result' => [
                'class' => '\mitrm\gourlio\ResultAction',
                'callback' => [$this, 'resultCallbackGourlio'],
            ]
        ];
    }

    /**
     * Обработка оповещения о платеже с gourl.io
     * @param $cryptobox Cryptobox
     * @param $return_data
     * @return string
     */
    public function resultCallbackGourlio($cryptobox, $return_data)
    {
        $model = PaymentRequest::findOne(['id' => $return_data['params']['order'], 'user_id' => $return_data['params']['user']]);
        if (!$model) {
            throw new BadRequestHttpException('Транзакция не найдена');
        }
        $data = [
            'order_id' => $model->id,
            'user_id' => Yii::$app->user->id,
            'amount' => $model->sum,
            'coinName' => $model->currency, // speedcoin, bitcoin, ...
        ];
        $cryptobox->load($data);
        if($cryptobox->isPaid()) {
            $model->sum = $return_data['params']['amount'];
            $model->status_id = PaymentRequest::STATUS_SUCCESS;
            $model->save();
        }
        return $return_data['text_return'];
    }


}
```

