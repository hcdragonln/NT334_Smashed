@extends('layout')

@section('content')
<div class="container">
    <h1>Dashboard</h1>
    <div class="row">
        <!-- Display counts -->
        <div class="col-md-12">
            <h3>Entity Counts</h3>
            <ul class="list-group">
                <li class="list-group-item">Pools: {{ $counts['pool'] }}</li>
                <li class="list-group-item">Cryptos: {{ $counts['crypto'] }}</li>
                <li class="list-group-item">Servers: {{ $counts['server'] }}</li>
                <li class="list-group-item">Ports: {{ $counts['port'] }}</li>
                <li class="list-group-item">Addresses: {{ $counts['address'] }}</li>
                <li class="list-group-item">Probes: {{ $counts['probes'] }}</li>
                <li class="list-group-item">History: {{ $counts['history'] }}</li>
            </ul>
        </div>
    </div>

    <div class="row">
        <!-- Summary Counts Chart -->
        <div class="col-md-6">
            <h3>Summary Counts</h3>
            <canvas id="summaryCountsChart"></canvas>
        </div>

        <!-- Currency Usage Pie Chart -->
        <div class="col-md-6">
            <h3>Currency Usage</h3>
            <canvas id="summaryCurrenciesChart"></canvas>
        </div>
    </div>

    <div class="row">
        <!-- Pools Multi Bar Chart -->
        <div class="col-md-12">
            <h3>Pools (FQDN and IP Counts)</h3>
            <canvas id="summaryPoolsChart"></canvas>
        </div>
    </div>
</div>
@endsection

@section('footer')
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/2.9.4/Chart.min.js"></script>

<script>
    window.onload = function() {
        // Summary Counts Chart
        var ctxCounts = document.getElementById('summaryCountsChart').getContext('2d');
        new Chart(ctxCounts, {
            type: 'bar',
            data: {
                labels: {!! json_encode(['Pools', 'Cryptos', 'Servers', 'Ports', 'Addresses']) !!},
                datasets: [{
                    label: 'Count',
                    data: {!! json_encode([$counts['pool'], $counts['crypto'], $counts['server'], $counts['port'], $counts['address']]) !!},
                    backgroundColor: ['#64B5F6', '#2196F3', '#1976D2', '#64B5F6', '#2196F3']
                }]
            },
            options: {
                responsive: true,
                title: {
                    display: true,
                    text: 'Entity Counts'
                }
            }
        });

        // Currency Usage Pie Chart
        var ctxCurrencies = document.getElementById('summaryCurrenciesChart').getContext('2d');
        new Chart(ctxCurrencies, {
            type: 'pie',
            data: {
                labels: {!! json_encode($currency_labels) !!},
                datasets: [{
                    label: 'Currencies',
                    data: {!! json_encode($currency_counts) !!},
                    backgroundColor: ['#64B5F6', '#2196F3', '#1976D2', '#64B5F6', '#2196F3']
                }]
            },
            options: {
                responsive: true,
                title: {
                    display: true,
                    text: 'Currency Usage'
                }
            }
        });

        // Pools Multi Bar Chart (FQDN and IP Counts)
        var ctxPools = document.getElementById('summaryPoolsChart').getContext('2d');
        new Chart(ctxPools, {
            type: 'bar',
            data: {
                labels: {!! json_encode($pool_labels) !!},
                datasets: [
                    {
                        label: 'FQDN Count',
                        data: {!! json_encode($pool_fqdn_counts) !!},
                        backgroundColor: '#64B5F6'
                    },
                    {
                        label: 'IP Count',
                        data: {!! json_encode($pool_addr_counts) !!},
                        backgroundColor: '#2196F3'
                    }
                ]
            },
            options: {
                responsive: true,
                title: {
                    display: true,
                    text: 'Pools (FQDN and IP Counts)'
                }
            }
        });
    };
</script>
@endsection
