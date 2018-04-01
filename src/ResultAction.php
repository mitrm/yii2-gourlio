<?php
namespace mitrm\gourlio;

use Yii;
use yii\base\InvalidConfigException;
use yii\web\BadRequestHttpException;

class ResultAction extends \yii\base\Action {

    public $name = 'gourlio'; //name component

    public $callback;

    /**
     * Runs the action.
     */
    public function run()
    {
        /** @var Cryptobox $cryptobox */
        $cryptobox = Yii::$app->get($this->name);
        if ($return_data = $cryptobox->checkWebhookData()) {
            return $this->callback($cryptobox, $return_data);
        }
        throw new BadRequestHttpException;
    }

    /**
     * @param Cryptobox $cryptobox
     * @param $nInvId
     * @param $nOutSum
     * @param $shp
     * @return mixed
     * @throws \yii\base\InvalidConfigException
     */
    protected function callback($cryptobox, $return_data)
    {
        if (!is_callable($this->callback)) {
            throw new InvalidConfigException('"' . get_class($this) . '::callback" should be a valid callback.');
        }
        $response = call_user_func($this->callback, $cryptobox, $return_data);
        return $response;
    }
}