<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy;

use LKDev\HetznerCloud\HetznerAPIClient;
use LKDev\HetznerCloud\Models\Zones\RRSetRequestOpts;

class DnsService implements DnsServiceInterface
{
    public function __construct(
        private readonly HetznerAPIClient $client,
        private readonly Config $config,
    ) {}

    public function update(RequestData $data): void
    {
        $zone = $this->client->zones()->getByName($data->zone);
        if ($zone === null) {
            throw new \RuntimeException('Zone not found: ' . $data->zone);
        }

        $rrSets = $zone->allRRSets(new RRSetRequestOpts($data->name, $data->type));
        $value = $data->type === 'TXT' ? '"' . addcslashes($data->value, '"\\') . '"' : $data->value;
        $record = [['value' => $value, 'comment' => '']];

        if (!empty($rrSets)) {
            $rrSet = $rrSets[0];
            if ($rrSet->ttl !== $this->config->recordTtl) {
                $rrSet->changeTTL($this->config->recordTtl);
            }
            $rrSet->setRecords($record);
            return;
        }

        $zone->createRRSet($data->name, $data->type, $record, $this->config->recordTtl);
    }

    public function clean(RequestData $data): void
    {
        $zone = $this->client->zones()->getByName($data->zone);
        if ($zone === null) {
            throw new \RuntimeException('Zone not found: ' . $data->zone);
        }

        $rrSets = $zone->allRRSets(new RRSetRequestOpts($data->name, $data->type));
        if (empty($rrSets)) {
            return;
        }

        $rrSets[0]->removeRecords($rrSets[0]->records);
    }
}
