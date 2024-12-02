# Generated by Django 5.0.6 on 2024-09-13 06:54

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('booker', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='store',
            name='subscribe',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='user',
            name='email',
            field=models.EmailField(blank=True, max_length=254, null=True, unique=True),
        ),
        migrations.CreateModel(
            name='Staff',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('role', models.CharField(choices=[('Manager', 'Manager'), ('Therapist', 'Therapist')], max_length=10)),
                ('phone', models.CharField(max_length=15)),
                ('email', models.EmailField(blank=True, max_length=254, null=True)),
                ('schedule', models.JSONField()),
                ('store', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='booker.store')),
            ],
        ),
    ]