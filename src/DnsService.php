<?php

declare(strict_types=1);

namespace HetznerDnsapiProxy;

use LKDev\HetznerCloud\HetznerAPIClient;
use LKDev\HetznerCloud\Models\Zones\Record;
use LKDev\HetznerCloud\Models\Zones\RRSetRequestOpts;
use LKDev\HetznerCloud\Models\Zones\Zones;

class DnsService implements DnsServiceInterface
{
    private readonly Zones $zones;

    public function __construct(
        HetznerAPIClient $client,
        private readonly Config $config,
    ) {
        // HetznerAPIClient::zones() declares no return type, so narrow it once
        // here rather than working with an untyped value throughout.
        $zones = $client->zones();
        if (!$zones instanceof Zones) {
            throw new \RuntimeException('Hetzner SDK returned an unexpected zones client');
        }
        $this->zones = $zones;
    }

    public function update(RequestData $data): void
    {
        $zone = $this->zones->getByName($data->zone);
        if ($zone === null) {
            throw new \RuntimeException('Zone not found: ' . $data->zone);
        }

        $rrSets = $zone->allRRSets(new RRSetRequestOpts($data->name, $data->type));
        $value = $data->type === 'TXT' ? '"' . addcslashes($data->value, '"\\') . '"' : $data->value;
        $record = [new Record($value, '')];

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
        $zone = $this->zones->getByName($data->zone);
        if ($zone === null) {
            throw new \RuntimeException('Zone not found: ' . $data->zone);
        }

        $rrSets = $zone->allRRSets(new RRSetRequestOpts($data->name, $data->type));
        if (empty($rrSets)) {
            return;
        }

        // RRSet::$records is declared as a bare array but is populated with
        // Record objects by RRSet::parse(); narrow it rather than assume.
        $rrSet = $rrSets[0];
        $records = array_values(array_filter(
            $rrSet->records,
            static fn (mixed $record): bool => $record instanceof Record,
        ));
        $rrSet->removeRecords($records);
    }
}
